#!/usr/bin/env python3
"""Reproduce the pinned Wireshark/IEEE prefix audit without importing code/data.

Place the files listed in research/wireshark-manufacturer-review.json under the
source directory, retaining their relative paths. No upstream Python/C executes.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-dir', type=Path, default=root / 'research/downloads/wireshark')
args = parser.parse_args()
reference = json.loads((root / 'research/wireshark-manufacturer-review.json').read_text())


def checked(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit(f'SHA-256 mismatch: {path}')
    return data


sources = {entry['path']: checked(args.source_dir / entry['path'], entry['sha256'])
           for entry in reference['sources']}
rows = set()
counts = Counter()
section = None
for line in sources['epan/manuf-data.c'].decode().splitlines():
    match = re.search(r'global_manuf_oui(24|28|36)_table', line)
    if match:
        section = int(match[1])
        continue
    if line == '};':
        section = None
        continue
    if section is None:
        continue
    match = re.fullmatch(r'\s*\{ \{ (.*?) \}, ("(?:\\.|[^"\\])*"),\s*("(?:\\.|[^"\\])*") \},', line)
    if not match:
        raise SystemExit('Unexpected manufacturer row syntax')
    octets = re.findall(r'0x([0-9A-F]{2})', match[1])
    encoded = ''.join(octets)
    if len(octets) != (section + 7) // 8 or (section % 8 and not encoded.endswith('0')):
        raise SystemExit('Unexpected prefix width/padding')
    prefix = encoded[:section // 4]
    if prefix in rows:
        raise SystemExit('Duplicate manufacturer prefix')
    rows.add(prefix)
    counts[str(section)] += 1

index = reference['lantern_index']
ieee = {}
for line in gzip.decompress(checked(root / index['path'], index['sha256'])).decode().splitlines():
    prefix, name, registry = line.split('\t')
    ieee[prefix] = (name, registry)
extra, missing = rows - ieee.keys(), ieee.keys() - rows
wka = []
for line in sources['wka'].decode().splitlines():
    line = line.split('#')[0].strip()
    if line:
        wka.append(line.split(None, 1)[0])
result = {
    'revision': reference['revision'],
    'wireshark_rows': len(rows), 'by_prefix_bits': dict(counts),
    'lantern_ieee_rows': len(ieee), 'shared_prefixes': len(rows & ieee.keys()),
    'wireshark_only_prefixes': len(extra),
    'wireshark_only_locally_administered': sum(bool(int(p[:2], 16) & 2) for p in extra),
    'wireshark_only_global_unicast': sum(not int(p[:2], 16) & 3 for p in extra),
    'lantern_only_prefixes': len(missing),
    'lantern_only_by_registry': dict(Counter(ieee[p][1] for p in missing)),
    'lantern_only_registration_authority': sum(ieee[p][0] == 'IEEE Registration Authority' for p in missing),
    'wka_rows': len(wka),
    'wka_multicast_rows': sum(bool(int(k[:2], 16) & 1) for k in wka),
    'wka_locally_administered_rows': sum(bool(int(k[:2], 16) & 2) for k in wka),
}
if result != reference['comparison']:
    raise SystemExit('Comparison differs from recorded audit')
print(json.dumps(result, indent=2, sort_keys=True))
