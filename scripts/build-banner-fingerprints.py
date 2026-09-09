#!/usr/bin/env python3
"""Import the pinned BSD-2-Clause Recog SSH/HTTP data without executing upstream code."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET
import xml.parsers.expat

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'd3d20938da9f5f1e442c2419fe6c30cd651b6878'
FILES = {
    'xml/ssh_banners.xml': 'a3e608cd8a46a177b6407875d7e31a34157c858cc9e3393920a99405e1f4f4b6',
    'xml/http_servers.xml': '010af0e05688945f669fd804520acf65b0160f89fc7702cc7faf12989a213302',
}


def extract(data):
    if b'\x00' in data or b'<!DOCTYPE' in data or b'<!ENTITY' in data:
        raise ValueError('XML declarations are not supported')
    root = ET.fromstring(data)
    if root.tag != 'fingerprints' or root.get('matches') not in ('ssh.banner', 'http_header.server'):
        raise ValueError('Unexpected input field')
    lines = []
    locations = xml.parsers.expat.ParserCreate()
    locations.StartElementHandler = lambda name, attrs: lines.append(locations.CurrentLineNumber) if name == 'fingerprint' else None
    locations.Parse(data, True)
    if len(lines) != len(root):
        raise ValueError('Unexpected fingerprint topology')
    rows, examples = [], []
    for number, (node, line) in enumerate(zip(root, lines)):
        if node.tag != 'fingerprint' or set(node.attrib) - {'pattern', 'certainty'}:
            raise ValueError('Unsupported fingerprint attributes')
        if any(c.tag not in ('param', 'description', 'example') for c in node):
            raise ValueError('Unsupported fingerprint content')
        descriptions = node.findall('description')
        if len(descriptions) != 1 or list(descriptions[0]):
            raise ValueError('Missing/complex description')
        row = {'pattern': node.attrib['pattern'], 'name': ' '.join((descriptions[0].text or '').split()),
               'line': line, 'params': []}
        if node.get('certainty'):
            row['certainty'] = node.get('certainty')
        names = set()
        for p in node.findall('param'):
            if set(p.attrib) - {'pos', 'name', 'value'} or list(p):
                raise ValueError('Unsupported parameter')
            name = p.attrib['name']
            if name in names or not re.fullmatch(r'[a-z_][a-z0-9_.-]*', name):
                raise ValueError('Duplicate/invalid parameter name')
            names.add(name)
            if not re.fullmatch(r'0|[1-9][0-9]*', p.attrib['pos']):
                raise ValueError('Invalid capture position')
            position = int(p.attrib['pos'])
            value = p.get('value', '')
            if (position == 0 and not value) or (position > 0 and value):
                raise ValueError('Invalid static/capture parameter')
            param = {'name': name, 'pos': position}
            if value:
                param['value'] = value
            row['params'].append(param)
        rows.append(row)
        for e in node.findall('example'):
            if list(e) or any(k.startswith('_') for k in e.attrib):
                raise ValueError('External/encoded examples are unsupported')
            examples.append({'rule': number, 'input': e.text or '', 'fields': e.attrib})
    return {'field': root.attrib['matches'], 'protocol': root.attrib['protocol'],
            'preference': root.attrib['preference'], 'rules': rows}, examples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'research/downloads/recog')
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args()
    reference = json.loads((ROOT / 'research/banner-catalog-review.json').read_text())['catalogs']['recog']
    required = [e for e in reference['sources'] if e['path'] in FILES or e['path'] in ('LICENSE', 'COPYING')]
    inputs = {}
    for entry in required:
        path = args.source_dir / entry['path']
        if args.download:
            with urllib.request.urlopen(entry['url'], timeout=30) as response:
                data = response.read(1024 * 1024)
        else:
            data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError(f'SHA-256 mismatch: {entry["path"]}')
        if entry['path'] in FILES and entry['sha256'] != FILES[entry['path']]:
            raise ValueError('Unexpected source revision')
        inputs[entry['path']] = data
        if args.download:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    catalogs, fixtures = [], []
    for path in FILES:
        catalog, examples = extract(inputs[path])
        catalog['source'] = f'https://github.com/rapid7/recog/blob/{REVISION}/{path}'
        catalogs.append(catalog)
        fixtures.append({'field': catalog['field'], 'examples': examples})
    def encode(value):
        output = io.BytesIO()
        with gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=9, mtime=0) as stream:
            stream.write(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode())
        return output.getvalue()
    index, tests = encode(catalogs), encode(fixtures)
    manifest = {'source': 'Rapid7 Recog', 'revision': REVISION, 'license': 'BSD-2-Clause', 'sources': required,
                'index_sha256': hashlib.sha256(index).hexdigest(), 'testdata_sha256': hashlib.sha256(tests).hexdigest(),
                'patterns': {c['field']: len(c['rules']) for c in catalogs},
                'selection': 'All pinned SSH and HTTP Server patterns, in upstream order. Parameters, certainty, preference, and source lines retained. Examples are test data only.'}
    # Validate all inputs and construct all outputs before replacing any artifact.
    (ROOT / 'pkg/fingerprints/data/recog.json.gz').write_bytes(index)
    (ROOT / 'pkg/fingerprints/testdata/examples.json.gz').write_bytes(tests)
    (ROOT / 'pkg/fingerprints/data/sources.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Imported {sum(len(c["rules"]) for c in catalogs)} patterns and {sum(len(f["examples"]) for f in fixtures)} test examples')


if __name__ == '__main__':
    main()
