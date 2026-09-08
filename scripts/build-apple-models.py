#!/usr/bin/env python3
"""Build a data-only AppleDB index; verify every input blob against a pinned Git tree.

Reads the downloaded archive directly. Does not extract paths, import upstream
modules, or execute upstream code. Hardware identifiers can map to several names.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import re
import tarfile
import urllib.request
import concurrent.futures
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '95f799d28e45dc110ee2f25b7e3e6cf8c1124dae'
LICENSE_SHA256 = '3adfabae22593bddd85f117ca55f6250ef115426f09dac48c1a8b2fc5fb53df3'
TREE_SHA = '44e9a4421c301987e5a70fe177086cb277296547'
REPOSITORY = 'https://github.com/littlebyteorg/appledb'
EXCLUDED_TYPES = {'Software', 'SDK', 'Simulator', 'Virtual Machine'}
IDENTIFIER = re.compile(r'[A-Za-z][A-Za-z0-9]*,[0-9]+')


def download_source(source):
    source.mkdir(parents=True, exist_ok=True)
    urls = {
        'commit.json': (f'https://api.github.com/repos/littlebyteorg/appledb/commits/{COMMIT}', 1_000_000),
        'deviceFiles-tree.json': (f'https://api.github.com/repos/littlebyteorg/appledb/git/trees/{TREE_SHA}?recursive=1', 5_000_000),
        'LICENSE': (f'https://raw.githubusercontent.com/littlebyteorg/appledb/{COMMIT}/LICENSE', 16_384),
        'source.tar.gz': (f'https://codeload.github.com/littlebyteorg/appledb/tar.gz/{COMMIT}', 104_857_600),
    }
    def fetch(item):
        name, (url, limit) = item
        temporary = source / (name + '.download')
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'Lantern-catalog-builder'})
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open('wb') as output:
                total = 0
                while chunk := response.read(65536):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError(f'Download exceeds limit: {name}')
                    output.write(chunk)
            temporary.replace(source / name)
        finally:
            temporary.unlink(missing_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch, urls.items()))


def build(source, output, retrieved):
    commit = json.loads((source / 'commit.json').read_text())
    if commit['sha'] != COMMIT:
        raise ValueError('Review and pin the new revision before refreshing the catalog')
    tree = json.loads((source / 'deviceFiles-tree.json').read_text())
    if tree.get('truncated') or tree.get('sha') != TREE_SHA:
        raise ValueError('Incomplete device inventory')
    expected = {f"deviceFiles/{e['path']}": e['sha'] for e in tree['tree']
                if e['type'] == 'blob' and e['path'].endswith('.json')}
    if len(expected) < 1500:
        raise ValueError('Unexpectedly small source inventory')
    models, observed = {}, set()
    archive_path = source / 'source.tar.gz'
    license_bytes = (source / 'LICENSE').read_bytes()
    archive_license = None
    with tarfile.open(archive_path) as archive:
        for member in archive:
            prefix = f'appledb-{COMMIT}/'
            if member.name == prefix.rstrip("/") and member.isdir():
                continue
            if not member.name.startswith(prefix):
                raise ValueError('Unexpected archive root')
            path = member.name[len(prefix):]
            if path == 'LICENSE':
                if not member.isfile() or member.size > 16_384:
                    raise ValueError('Invalid license member')
                archive_license = archive.extractfile(member).read()
            if path not in expected:
                continue
            if path in observed or not member.isfile() or member.size > 2_000_000:
                raise ValueError(f'Invalid member: {path}')
            data = archive.extractfile(member).read()
            blob_hash = hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest()
            if blob_hash != expected[path]:
                raise ValueError(f'Git blob mismatch: {path}')
            observed.add(path)
            row = json.loads(data)
            if row.get('internal') or row['type'] in EXCLUDED_TYPES:
                continue
            identifiers = row.get('identifier', [])
            if isinstance(identifiers, str):
                identifiers = [identifiers]
            if not isinstance(identifiers, list) or not all(isinstance(i, str) for i in identifiers):
                raise ValueError(f'Invalid identifiers: {path}')
            for identifier in identifiers:
                if not IDENTIFIER.fullmatch(identifier):
                    continue
                name, kind = row['name'], row['type']
                if any(not isinstance(v, str) or not v or len(v) > 256 or any(ord(c) < 32 for c in v)
                       for v in (name, kind, identifier)):
                    raise ValueError(f'Invalid display data: {path}')
                entry = {'identifier': identifier, 'name': name, 'type': kind,
                         'manufacturer': 'Beats' if kind.startswith('Beats ') else 'Apple',
                         'path': path, 'sha256': hashlib.sha256(data).hexdigest()}
                models.setdefault(identifier.lower(), []).append(entry)
    if observed != set(expected) or archive_license != license_bytes:
        raise ValueError('Incomplete archive or license mismatch')
    if hashlib.sha256(license_bytes).hexdigest() != LICENSE_SHA256:
        raise ValueError('Upstream license changed; review before import')
    models = {k: sorted(v, key=lambda r: (r['name'], r['path'])) for k, v in sorted(models.items())}
    index = json.dumps(models, ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
    compressed = gzip.compress(index, mtime=0)
    metadata = {'name': 'AppleDB', 'url': REPOSITORY, 'commit': COMMIT,
                'license': 'MIT', 'retrieved': retrieved,
                'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                'license_sha256': hashlib.sha256(license_bytes).hexdigest(),
                'index_sha256': hashlib.sha256(index).hexdigest(),
                'input_records': len(observed), 'identifiers': len(models),
                'assignments': sum(len(v) for v in models.values()),
                'ambiguous_identifiers': sum(len({e['name'] for e in v}) > 1 for v in models.values()),
                'selection': 'Public hardware identifiers in family,number form; internal, software, SDK, simulator, and virtual-machine entries excluded. Every source assignment retained.'}
    output.mkdir(parents=True, exist_ok=True)
    (output / 'apple-models.json.gz').write_bytes(compressed)
    (output / 'sources.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(f"Imported {metadata['identifiers']} identifiers / {metadata['assignments']} assignments; {metadata['ambiguous_identifiers']} identifiers have multiple names; {len(compressed)} bytes compressed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download', action='store_true', help='fetch the pinned public source before importing')
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'research/downloads/appledb')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'pkg/models/data')
    parser.add_argument('--retrieved', default=datetime.date.today().isoformat())
    args = parser.parse_args()
    datetime.date.fromisoformat(args.retrieved)
    if args.download:
        download_source(args.source_dir)
    build(args.source_dir, args.output_dir, args.retrieved)
