#!/usr/bin/env python3
"""Test importer boundaries; run with PyYAML==6.0.3 installed."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('matter_import', Path(__file__).with_name('build-matter-models.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

document = '''matterManufacturer:
  - vendorId: 0x115f
    productId: 0x2002
    deviceLabel: Label one
  - vendorId: 4447
    productId: 8194
    deviceLabel: Label two
  - vendorId: 4447
    productId: 8194
    deviceLabel: Conditional label
    productName: Extra condition
  - vendorId: 65521
    productId: 32769
    deviceLabel: SDK test
  - vendorId: true
    productId: 8194
    deviceLabel: Boolean ID
  - vendorId: 4447
    deviceLabel: Generic vendor
matterGeneric:
  - deviceLabel: Generic light
'''
count, rows = module.extract(document, 'fixture.yml', 'digest')
assert count == 6 and [row['name'] for row in rows] == ['Label one', 'Label two'], rows
assert all(row['identifier'] == 'matter:4447:8194' for row in rows)
for invalid in ('matterManufacturer: []\nmatterManufacturer: []',
                'matterManufacturer:\n  - vendorId: 1\n    vendorId: 2',
                'matterManufacturer: !!python/object/apply:builtins.print [unsafe]'):
    try:
        module.extract(invalid, 'fixture.yml', 'digest')
    except (ValueError, module.yaml.YAMLError):
        continue
    raise AssertionError('Ambiguous or executable YAML accepted')
print('PASS Matter import: exact numeric pairs, ambiguity preserved, conditional/generic/test/invalid entries excluded, duplicate keys and executable YAML rejected')
