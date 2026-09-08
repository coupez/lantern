#!/usr/bin/env python3
"""Reproduce the pinned Nmap/Recog source review; no catalog data is imported.

Requires the manifest's public inputs under research/downloads/{nmap,recog},
plus the local Go toolchain. Upstream code is never executed. Run at repo root.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'research/banner-catalog-review.json'


def checked(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f'SHA-256 mismatch: {path}')
    return data


def review(reference, source_dir):
    inputs = {}
    for source, metadata in reference['catalogs'].items():
        inputs[source] = {entry['path']: checked(source_dir / source / entry['path'], entry['sha256'])
                          for entry in metadata['sources']}
    index = reference['lantern_index']
    ieee = {}
    for line in gzip.decompress(checked(ROOT / index['path'], index['sha256'])).decode().splitlines():
        prefix, name, registry = line.split('\t')
        if prefix in ieee:
            raise ValueError('Duplicate IEEE prefix')
        ieee[prefix] = (name, registry)
    prefixes = {}
    for line in inputs['nmap']['nmap-mac-prefixes'].decode().splitlines():
        if not line or line.startswith('#'):
            continue
        prefix, name = line.split(None, 1)
        if not re.fullmatch(r'(?:[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9})', prefix) or prefix in prefixes:
            raise ValueError('Invalid/duplicate Nmap prefix')
        prefixes[prefix] = name
    extra = prefixes.keys() - ieee.keys()
    missing = ieee.keys() - prefixes.keys()
    probes = Counter()
    match_lines = 0
    softmatch_lines = 0
    for line in inputs['nmap']['nmap-service-probes'].decode().splitlines():
        if line.startswith('Probe '):
            probes[line.split()[1]] += 1
        match_lines += line.startswith('match ')
        softmatch_lines += line.startswith('softmatch ')
    paths = ['xml/ssh_banners.xml', 'xml/http_servers.xml']
    result = subprocess.run(['go', 'run', str(ROOT / 'scripts/check-recog-patterns.go'),
                             *[str(source_dir / 'recog' / path) for path in paths]],
                            cwd=ROOT, check=True, capture_output=True, text=True, timeout=90)
    compatibility = json.loads(result.stdout)
    if len(compatibility) != len(paths):
        raise ValueError('Wrong number of Go compatibility results')
    for path, row in zip(paths, compatibility):
        if row['sha256'] != hashlib.sha256(inputs['recog'][path]).hexdigest():
            raise ValueError('Go inspected a different XML input')
    return {
        'nmap': {
            'prefixes': len(prefixes),
            'by_prefix_bits': dict(Counter(str(len(p) * 4) for p in prefixes)),
            'lantern_ieee_prefixes': len(ieee),
            'shared_prefixes': len(prefixes.keys() & ieee.keys()),
            'nmap_only_prefixes': len(extra),
            'nmap_only_local': sum(bool(int(p[:2], 16) & 2) for p in extra),
            'nmap_only_multicast': sum(bool(int(p[:2], 16) & 1) for p in extra),
            'nmap_only_global_unicast': sum(not int(p[:2], 16) & 3 for p in extra),
            'lantern_only_prefixes': len(missing),
            'probes_by_transport': dict(probes),
            'match_lines': match_lines,
            'softmatch_lines': softmatch_lines,
        },
        'recog': dict(zip(paths, compatibility)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'research/downloads')
    args = parser.parse_args()
    reference = json.loads(MANIFEST.read_text())
    result = review(reference, args.source_dir.resolve())
    if result != reference['comparison']:
        raise SystemExit('Source review differs from recorded audit')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
