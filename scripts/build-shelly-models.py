#!/usr/bin/env python3
"""Extract literal model names/generations without importing or executing aioshelly."""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request

COMMIT = '8f1b2f9bf2fc154faf6c3d73213d59620a6e301c'
SOURCE_SHA256 = 'a24c482a0eb06e8f00f714490dfd256d4026c7cd24fb2921b9f20623b45c416d'
LICENSE_SHA256 = 'a265d325ac5d9090ecffdbe0198c15237c2349cf16f8409de7e35ae3c5b769bf'
REPO = 'https://github.com/home-assistant-libs/aioshelly'
root = Path(__file__).resolve().parents[1]
source = root / 'research/downloads/aioshelly'


def extract(content):
    constants, table = {}, None
    for node in ast.parse(content).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if isinstance(node.value, ast.Constant):
            constants[name] = node.value.value
        elif name == 'DEVICES':
            if table is not None or not isinstance(node.value, ast.Dict):
                raise ValueError('Unexpected device table')
            table = node.value
    if table is None:
        raise ValueError('Missing device table')
    def literal(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return constants[node.id]
        raise ValueError('Non-literal model field')
    index = {}
    for key, value in zip(table.keys, table.values):
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name) or value.func.id != 'ShellyDevice' or value.args:
            raise ValueError('Unexpected device entry')
        kwargs = {k.arg: k.value for k in value.keywords}
        if None in kwargs or len(kwargs) != len(value.keywords):
            raise ValueError('Ambiguous device fields')
        identifier, name, generation = literal(key), literal(kwargs['name']), literal(kwargs['gen'])
        if literal(kwargs['model']) != identifier or type(identifier) is not str or type(name) is not str or type(generation) is not int:
            raise ValueError('Invalid model identity')
        if not identifier or not name or generation not in (1, 2, 3, 4) or any(ord(c) < 32 for c in identifier + name):
            raise ValueError('Invalid model data')
        row = {'identifier': identifier, 'name': name, 'generation': generation}
        bucket = index.setdefault(identifier.lower(), [])
        if row in bucket:
            raise ValueError('Duplicate catalog record')
        bucket.append(row)
    for rows in index.values():
        rows.sort(key=lambda r: (r['generation'], r['name']))
    return dict(sorted(index.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--retrieved', required=True, type=datetime.date.fromisoformat)
    args = parser.parse_args()
    if args.download:
        source.mkdir(parents=True, exist_ok=True)
        for path in ('aioshelly/const.py', 'LICENSE'):
            url = f'https://raw.githubusercontent.com/home-assistant-libs/aioshelly/{COMMIT}/{path}'
            with urllib.request.urlopen(url, timeout=30) as response:
                (source / Path(path).name).write_bytes(response.read())
    content, license_text = (source / 'const.py').read_bytes(), (source / 'LICENSE').read_bytes()
    if hashlib.sha256(content).hexdigest() != SOURCE_SHA256 or hashlib.sha256(license_text).hexdigest() != LICENSE_SHA256:
        raise ValueError('Pinned source/license hash mismatch')
    index = extract(content)
    if len(index) != 155 or sum(map(len, index.values())) != 155:
        raise ValueError('Unexpected pinned catalog count')
    data = (json.dumps(index, indent=2, ensure_ascii=False) + '\n').encode()
    provenance = {'name': 'aioshelly', 'url': REPO, 'commit': COMMIT, 'license': 'Apache-2.0',
                  'retrieved': args.retrieved.isoformat(), 'source_sha256': SOURCE_SHA256,
                  'license_sha256': LICENSE_SHA256, 'index_sha256': hashlib.sha256(data).hexdigest(),
                  'input_records': 155, 'identifiers': len(index), 'assignments': sum(map(len, index.values())),
                  'ambiguous_identifiers': sum(len(v) > 1 for v in index.values()),
                  'selection': 'DEVICES model identifier, name and generation; includes all catalog entries, irrespective of upstream control support. No firmware minimum, capability, control or Bluetooth-ID data imported.'}
    (root / 'pkg/models/data/shelly-models.json').write_bytes(data)
    (root / 'pkg/models/data/shelly-sources.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(f'Imported {len(index)} Shelly identifiers from {COMMIT}')


if __name__ == '__main__':
    main()
