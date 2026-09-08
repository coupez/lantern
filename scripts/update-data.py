#!/usr/bin/env python3
"""Refresh build-time public registries. No Fing services or keys are used."""
import csv
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
IEEE = [('oui', 'oui/oui.csv'), ('mam', 'oui28/mam.csv'), ('oui36', 'oui36/oui36.csv'), ('iab', 'iab/iab.csv')]
IANA = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Lantern registry builder/0.1'})
    with urllib.request.urlopen(req, timeout=60) as response:
        content = response.read(20 * 1024 * 1024 + 1)
    if len(content) > 20 * 1024 * 1024:
        raise ValueError(f'Registry exceeds size limit: {url}')
    return content

def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.registry-')
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def main():
    date = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    vendors, sources, raw = {}, [], {}
    for name, suffix in IEEE:
        url = 'https://standards-oui.ieee.org/' + suffix
        content = fetch(url)
        rows = list(csv.DictReader(io.StringIO(content.decode('utf-8-sig'))))
        if len(rows) < 1000:
            raise ValueError(f'Unexpectedly small registry: {url}')
        for row in rows:
            prefix = row['Assignment'].upper()
            if len(prefix) not in (6, 7, 9) or any(c not in '0123456789ABCDEF' for c in prefix):
                raise ValueError(f'Invalid assignment {prefix}')
            vendor = row['Organization Name'].replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
            vendors[prefix] = (vendor, row['Registry'])
        sources.append(dict(url=url, sha256=hashlib.sha256(content).hexdigest(), rows=len(rows)))
        raw[name + '.csv'] = content
    content = fetch(IANA)
    services = {}
    for row in csv.DictReader(io.StringIO(content.decode('utf-8-sig'))):
        if row['Transport Protocol'] == 'tcp' and row['Port Number'].isdigit() and row['Service Name']:
            services.setdefault(int(row['Port Number']), row['Service Name'])
    if len(services) < 5000:
        raise ValueError('Unexpectedly small IANA registry')
    # All downloads and validations finish before replacing generated artifacts.
    vendor_text = ''.join(f'{p}\t{v}\t{r}\n' for p, (v, r) in sorted(vendors.items()))
    service_text = ''.join(f'{p}\t{v}\n' for p, v in sorted(services.items()))
    outputs = {
        'pkg/vendors/data/ieee.tsv.gz': gzip.compress(vendor_text.encode(), mtime=0),
        'pkg/vendors/data/sources.json': (json.dumps(dict(retrieved=date, assignments=len(vendors), sources=sources), indent=2) + '\n').encode(),
        'pkg/scanner/data/iana-tcp.tsv.gz': gzip.compress(service_text.encode(), mtime=0),
        'pkg/scanner/data/sources.json': (json.dumps(dict(url=IANA, retrieved=date, sha256=hashlib.sha256(content).hexdigest(), tcp_assignments=len(services)), indent=2) + '\n').encode(),
    }
    for name, data in raw.items():
        atomic(ROOT / 'research/downloads' / name, data)
    atomic(ROOT / 'research/downloads/iana-services.csv', content)
    for path, data in outputs.items():
        atomic(ROOT / path, data)
    print(f'Updated {len(vendors):,} MAC assignments and {len(services):,} TCP services. Run make build.')

if __name__ == '__main__':
    main()
