#!/usr/bin/env python3
"""Reproduce the pinned FTP/SMTP catalog review; never import runtime data."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'research/greeting-catalog-review.json'


def checked(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Source SHA-256 mismatch')
    return data


def check_patterns(paths, flags=False):
    command = ['go', 'run', str(ROOT / 'scripts/check-recog-patterns.go')]
    if flags:
        command.append('--ruby-flags')
    result = subprocess.run(command + [str(path) for path in paths], cwd=ROOT,
                            check=True, capture_output=True, text=True, timeout=90)
    return json.loads(result.stdout)


def self_test():
    root = ET.Element('fingerprints')
    cases = [
        ('^case$', 'REG_ICASE', 'CASE'),
        ('^second$', '', 'first\nsecond'),
        ('^first.second$', 'REG_MULTILINE', 'first\nsecond'),
        ('^first.second$', 'REG_DOT_NEWLINE', 'first\nsecond'),
        ('^first.second$', 'REG_LINE_ANY_CRLF', 'first\nsecond'),
        ('^first.second$', 'REG_ICASE,REG_MULTILINE', 'FIRST\nSECOND'),
        ('^first.second$', '', 'first\nsecond'),
        ('^unknown$', 'UNSUPPORTED', 'unknown'),
    ]
    for pattern, flags, text in cases:
        rule = ET.SubElement(root, 'fingerprint', pattern=pattern, flags=flags)
        ET.SubElement(rule, 'example').text = text
    with tempfile.TemporaryDirectory(prefix='lantern-recog-flags-') as directory:
        path = Path(directory)/'examples.xml'; path.write_bytes(ET.tostring(root))
        result = check_patterns([path], True)[0]
    assert result['issues'] == ['pattern 7: unsupported flag "UNSUPPORTED"',
                                'pattern 6 example 0 does not match'], result
    try:
        checked(b'changed input', hashlib.sha256(b'original input').hexdigest())
    except ValueError:
        pass
    else:
        raise AssertionError('Changed source accepted')
    print('PASS flag-model cases, unsupported flag rejection, and source hash check')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=ROOT/'research/downloads/recog')
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    manifest = json.loads(MANIFEST.read_text())
    inputs = {}
    for entry in manifest['sources']:
        path = args.source_dir/entry['path']
        if args.download:
            with urllib.request.urlopen(entry['url'], timeout=30) as response:
                data = response.read(1024*1024)
            checked(data, entry['sha256'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        else:
            data = checked(path.read_bytes(), entry['sha256'])
        inputs[entry['path']] = data
    for name, expected in manifest['catalogs'].items():
        root = ET.fromstring(inputs[name]); examples = root.findall('fingerprint/example')
        actual = {'field':root.get('matches'), 'protocol':root.get('protocol'), 'preference':root.get('preference'),
                  'flags':dict(Counter(node.get('flags','') for node in root)),
                  'multiline_examples':sum('\n' in (e.text or '') or '\r' in (e.text or '') for e in examples),
                  'example_assertions':sum(len(e.attrib) for e in examples)}
        assert actual == expected, name
    paths = [args.source_dir/name for name in manifest['catalogs']]
    for flags, key in [(False, 'plain_go_baseline'), (True, 'ruby_flag_model')]:
        actual = check_patterns(paths, flags)
        assert actual == manifest[key], key
        for path, result in zip(paths, actual):
            assert result['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    print('PASS pinned FTP/SMTP review: 290 patterns, 550 examples, 1095 positional assertions; four other assertions not evaluated')


if __name__ == '__main__':
    main()
