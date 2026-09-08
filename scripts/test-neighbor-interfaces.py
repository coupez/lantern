#!/usr/bin/env python3
"""Real Linux neighbor-table isolation. Run only in the dedicated test container."""
import json
from pathlib import Path
import subprocess
import sys

if not Path('/.dockerenv').exists():
    raise SystemExit('This fixture requires an isolated Docker container with CAP_NET_ADMIN.')
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/lantern').resolve())

def ip(*args):
    return subprocess.run(['ip', *args], check=True, capture_output=True, text=True, timeout=5)

ip('link', 'add', 'lantern0', 'type', 'veth', 'peer', 'name', 'lantern1')
try:
    for iface, mac in [('lantern0', '02:00:00:00:00:10'), ('lantern1', '02:00:00:00:00:11')]:
        ip('link', 'set', iface, 'up')
        for family, target in [('-4', '192.0.2.123'), ('-6', 'fe80::123'), ('-6', 'fd77:123::123')]:
            ip(family, 'neigh', 'add', target, 'lladdr', mac, 'dev', iface, 'nud', 'permanent')
    ip('-4', 'neigh', 'add', '192.0.2.124', 'lladdr', '02:00:00:00:00:10', 'dev', 'lantern0', 'nud', 'permanent')
    # Confirm the actual iproute2 format that originally broke scoped parsing.
    assert ' dev lantern0 ' in ip('-6', 'neigh', 'show').stdout
    assert ' dev lantern0 ' not in ip('-6', 'neigh', 'show', 'dev', 'lantern0').stdout
    def scan(iface, target):
        result = subprocess.run([binary, 'scan', target, '--interface', iface, '--ports', 'none', '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--json'], check=True, capture_output=True, text=True, timeout=10)
        assert not result.stderr, result.stderr
        report = json.loads(result.stdout)
        assert report['interface'] == iface and report['probed'] == 0 and not report.get('warnings'), report
        return report
    for iface, mac in [('lantern0', '02:00:00:00:00:10'), ('lantern1', '02:00:00:00:00:11')]:
        for target in ['192.0.2.123', 'fe80::123', 'fd77:123::123']:
            report = scan(iface, target)
            assert len(report['devices']) == 1, report
            device = report['devices'][0]
            expected_ip = target + '%' + iface if target.startswith('fe80:') else target
            assert device['ip'] == expected_ip and device['mac'] == mac, device
            assert device['evidence'] == ['neighbor-cache'] and not device.get('ports'), device
    assert not scan('lantern1', '192.0.2.124')['devices'], 'another link leaked into the selected scan'
    print('PASS real IPv4/IPv6 neighbor tables: duplicate IPs on separate links, scoped link-local addresses, correct MACs, cached-only evidence, wrong-link exclusion')
finally:
    ip('link', 'delete', 'lantern0')
