#!/usr/bin/env python3
"""Import pinned SmartThings Matter ID pairs/labels; requires PyYAML==6.0.3.

Use --download to fetch the pinned files, or --source-dir for local inputs.
Only SafeLoader data nodes are read; no source code is executed.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
REVISION = '71bbd3da8178b1c38332a6d9342ea23a3ce5b3dd'

class UniqueLoader(yaml.SafeLoader):
    pass

def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f'Duplicate YAML key: {key}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result

UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)

def extract(content, path, digest):
    data = yaml.load(content, Loader=UniqueLoader)
    if not isinstance(data, dict):
        raise ValueError('Expected a fingerprint mapping')
    rows = data.get('matterManufacturer') or []
    if not isinstance(rows, list):
        raise ValueError('Expected manufacturer fingerprint list')
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid fingerprint entry')
        if set(row) - {'id', 'vendorId', 'productId', 'deviceLabel', 'deviceProfileName'}:
            continue  # Additional conditions cannot be matched from VP alone.
        vid, pid, label = row.get('vendorId'), row.get('productId'), row.get('deviceLabel')
        if type(vid) is not int or type(pid) is not int or not isinstance(label, str):
            continue
        if not 0 < vid < 0xfff0 or not 0 < pid <= 0xffff:
            continue  # Unknown/reserved/test namespace is not retail identity.
        if not label.strip() or len(label) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in label):
            raise ValueError('Invalid product label')
        result.append({'identifier': f'matter:{vid}:{pid}', 'name': label, 'path': path, 'sha256': digest})
    return len(rows), result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'research/downloads/smartthings')
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args()
    manifest = ROOT / 'pkg/models/data/matter-sources.json'
    source = json.loads(manifest.read_text())
    if source['commit'] != REVISION or source['license'] != 'Apache-2.0':
        raise ValueError('Unexpected pinned source')
    inputs = source['input_sources'] + [{'path': 'LICENSE', 'sha256': source['license_sha256']}]
    contents = {}
    for entry in inputs:
        path = entry['path']
        if Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError('Unsafe source path')
        file = args.source_dir / path
        if args.download:
            url = f'https://raw.githubusercontent.com/SmartThingsCommunity/SmartThingsEdgeDrivers/{REVISION}/{path}'
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read(2 * 1024 * 1024 + 1)
            file.parent.mkdir(parents=True, exist_ok=True)
            if hashlib.sha256(content).hexdigest() != entry['sha256']:
                raise ValueError(f'Pinned hash mismatch: {path}')
            file.write_bytes(content)
        content = file.read_bytes()
        if hashlib.sha256(content).hexdigest() != entry['sha256']:
            raise ValueError(f'Pinned hash mismatch: {path}')
        contents[path] = content
    index, input_records = {}, 0
    for entry in source['input_sources']:
        count, rows = extract(contents[entry['path']], entry['path'], entry['sha256'])
        input_records += count
        for row in rows:
            bucket = index.setdefault(row['identifier'], [])
            if row not in bucket:
                bucket.append(row)
    for rows in index.values():
        rows.sort(key=lambda row: (row['name'], row['path']))
    data = (json.dumps(dict(sorted(index.items())), indent=2, ensure_ascii=False) + '\n').encode()
    source.update(index_sha256=hashlib.sha256(data).hexdigest(), input_records=input_records,
                  identifiers=len(index), assignments=sum(map(len,index.values())),
                  ambiguous_identifiers=sum(len({r['name'] for r in rows}) > 1 for rows in index.values()))
    if len(index) != 998:
        raise ValueError(f'Unexpected pinned index size: {len(index)}')
    (ROOT / 'pkg/models/data/matter-models.json.gz').write_bytes(gzip.compress(data, mtime=0))
    manifest.write_text(json.dumps(source, indent=2) + '\n')
    print(f'Imported {len(index)} Matter product identifier pairs')

if __name__ == '__main__':
    main()
