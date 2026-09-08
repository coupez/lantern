#!/usr/bin/env python3
"""Check actual doctor output. Opens local sockets; sends no discovery packets."""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('binary', nargs='?', default='bin/lantern')
parser.add_argument('--expect-arp', choices=['available', 'unavailable'])
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
interface = os.environ.get('LANTERN_ARP_INTERFACE')
selection = ['--interface', interface] if interface else []

def run(*flags):
    return subprocess.run([binary, 'doctor', *flags], capture_output=True, text=True, timeout=15)

result = run(*selection, '--json')
assert result.returncode == 0 and not result.stderr, result
report = json.loads(result.stdout)
assert report['schema'] == 1 and report['version'] and report['vendor_assignments'] > 0 and report['model_identifiers'] > 0
if os.environ.get('LANTERN_EXPECT_GOARCH'):
    assert report['os'] == 'linux' and report['arch'] == os.environ['LANTERN_EXPECT_GOARCH'], report
checks = {check['name']: check for check in report['checks']}
assert len(checks) == len(report['checks']) == 13, checks
assert checks['remote_reachability']['status'] == 'not_checked'
assert all(c['status'] in {'available', 'unavailable', 'not_checked'} and c['detail'] for c in checks.values())
assert all(c.get('hint') for c in checks.values() if c['status'] == 'unavailable')
if interface:
    assert report['interface'] == interface
    assert all(n['interface'] == interface for n in report['networks'])
if args.expect_arp:
    assert checks['arp']['status'] == args.expect_arp, checks['arp']
    assert checks['target4']['status'] == 'available', checks['target4']
    if args.expect_arp == 'unavailable':
        assert any(reason in checks['arp']['detail'].lower() for reason in ('permission denied', 'operation not permitted')), checks['arp']
plain = run(*selection)
assert plain.returncode == 0 and not plain.stderr, plain
assert 'no discovery packets sent' in plain.stdout and 'remote_reachability' in plain.stdout and '\x1b' not in plain.stdout
for flags in [('192.0.2.1',), ('--unknown',), ('--interface', 'lantern-doctor-missing', '--json')]:
    bad = run(*flags)
    assert bad.returncode != 0 and bad.stderr, (flags, bad)
print('PASS doctor CLI: structured/plain results, optional failure handling, interface selection, invalid input; ARP=' + checks['arp']['status'])
