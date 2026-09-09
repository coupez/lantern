#!/usr/bin/env python3
"""Import standard Matter 1.4 device-type labels from pinned Apache-2.0 XML.

Download each source URL in the generated source record to --source-dir first.
Only numeric IDs, display labels, and the application/utility distinction are
retained; no clusters, commands, implementation, or vendor-specific types.
"""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-dir', type=Path, default=root / 'research/downloads/matter-1.4')
args = parser.parse_args()
revision = '43aa98c2d30ee547c6b587b9de7bbb794f175ece'
inputs = {
    'src/app/zap-templates/zcl/data-model/chip/matter-devices.xml': '0daebaf3cd8fe4fb6650f7ee9112ef75e032cb732903ff5c14e4e9de7de8ce21',
    'src/lib/dnssd/TxtFields.h': '13ef2031e869d19c2d999bf5b3a2f7ee3511bbc016dc43b34763eae0be94690d',
    'src/lib/dnssd/TxtFields.cpp': 'e872463d258e49f88545e7970bea93ee2ec870fdd8124aba2a26440d3615e81c',
    'src/lib/dnssd/ServiceNaming.h': '98a1a7cb07d2dab873e65075a9265e1570dcbd91d49255af2490378f5a7622f1',
    'LICENSE': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4',
    'NOTICE': '8e576da197f576b82b633a037f7844cdf45e1a9142e6c7fc01793d9487a3a950',
}
for path, digest in inputs.items():
    content = (args.source_dir / Path(path).name).read_bytes()
    if hashlib.sha256(content).hexdigest() != digest:
        raise SystemExit(f'Pinned input hash mismatch: {path}')

types = {}
for node in ET.parse(args.source_dir / 'matter-devices.xml').getroot().findall('deviceType'):
    number = int(node.findtext('deviceId'), 16)
    if number > 0xffff:  # Exclude SDK examples and vendor-specific types.
        continue
    name = node.findtext('typeName')
    if not name.startswith('Matter ') or str(number) in types:
        raise SystemExit('Unexpected or repeated device-type definition')
    types[str(number)] = {'name': name.removeprefix('Matter '), 'application': node.findtext('class') == 'Simple'}
if len(types) != 65:
    raise SystemExit(f'Unexpected pinned device-type count: {len(types)}')
output = {
    'source': {
        'repository': 'https://github.com/project-chip/connectedhomeip',
        'revision': revision,
        'version': 'v1.4.0.0',
        'retrieved': '2026-09-08',
        'license': 'Apache-2.0',
        'copyright': 'Copyright (c) 2021 Project CHIP Authors',
        'selection': 'Standard 16-bit IDs only; strip Matter prefix; class Simple marks application types. No model/vendor mapping.',
        'inputs': [{'url': f'https://raw.githubusercontent.com/project-chip/connectedhomeip/{revision}/{path}', 'sha256': digest} for path, digest in inputs.items()],
    },
    'types': dict(sorted(types.items(), key=lambda item: int(item[0]))),
}
(root / 'pkg/scanner/data/matter-types.json').write_text(json.dumps(output, indent=2) + '\n')
print(f'Imported {len(types)} Matter device types')
