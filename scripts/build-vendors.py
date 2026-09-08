#!/usr/bin/env python3
"""Build deterministic offline IEEE index from downloaded public CSV registries."""
import csv, gzip, hashlib, json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
rows = {}
sources = []
for name, path in [('oui','oui/oui.csv'), ('mam','oui28/mam.csv'), ('oui36','oui36/oui36.csv'), ('iab','iab/iab.csv')]:
    file = root / 'research/downloads' / (name + '.csv')
    content = file.read_bytes()
    count = 0
    for row in csv.DictReader(content.decode('utf-8-sig').splitlines()):
        prefix = row['Assignment'].upper()
        vendor = row['Organization Name'].replace('\t',' ').replace('\n',' ')
        rows[prefix] = (vendor, row['Registry'])
        count += 1
    sources.append(dict(url='https://standards-oui.ieee.org/'+path, sha256=hashlib.sha256(content).hexdigest(), rows=count))
output = ''.join(f'{p}\t{v}\t{r}\n' for p,(v,r) in sorted(rows.items()))
(root/'pkg/vendors/data/ieee.tsv.gz').write_bytes(gzip.compress(output.encode(), mtime=0))
(root/'pkg/vendors/data/sources.json').write_text(json.dumps(dict(retrieved='2026-09-08',assignments=len(rows),sources=sources),indent=2)+'\n')
print(f'Built {len(rows):,} assignments')
