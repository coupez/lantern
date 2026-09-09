#!/usr/bin/env python3
"""Real Linux neighbor-table isolation. Run only in the dedicated test container."""
import csv
import io
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
    def scan(iface, target, output='json'):
        result = subprocess.run([binary, 'scan', target, '--interface', iface, '--ports', 'none', '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--' + output], check=True, capture_output=True, text=True, timeout=10)
        assert not result.stderr, result.stderr
        if output == 'csv':
            return list(csv.DictReader(io.StringIO(result.stdout)))
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
    for target, mac, name, identifier in [
            ('192.0.2.123', '00:00:5e:00:01:2a', 'VRRP/CARP', 42),
            ('fe80::123', '00:00:5e:00:02:ff', 'VRRP IPv6', 255),
            ('192.0.2.123', '00:00:0c:07:ac:00', 'HSRP v1', 0),
            ('192.0.2.123', '00:00:0c:9f:ff:ff', 'HSRP v2 IPv4', 4095),
            ('fd77:123::123', '00:05:73:a0:0f:ff', 'HSRP v2 IPv6', 4095)]:
        ip('-6' if ':' in target else '-4', 'neigh', 'replace', target, 'lladdr', mac,
           'dev', 'lantern0', 'nud', 'permanent')
        d = scan('lantern0', target)['devices'][0]
        role = d['vendor']['address_role']
        assert name in role['name'] and role['identifier'] == identifier and role['references'], d
        assert d['mac'] == mac and d['evidence'] == ['neighbor-cache'] and d['kind'] == 'device', d
        assert not d.get('identity') and not d.get('ports') and not d.get('advertisements'), d
        row = scan('lantern0', target, 'csv')[0]
        assert row['mac_address_role'] == role['name'] and row['mac_address_role_id'] == str(identifier), row
        assert row['vendor'] == d['vendor']['name'] and not row['manufacturer'] and not row['model'], row
        other = scan('lantern1', target)['devices'][0]
        assert other['vendor']['private'] and not other['vendor'].get('address_role'), other
    print('PASS real IPv4/IPv6 neighbor tables: duplicate IPs on separate links, scoped link-local addresses, correct MACs, cached-only evidence, wrong-link exclusion')
    print('PASS virtual MAC ranges from kernel neighbor tables: five range labels/IDs in JSON and CSV; no invented protocol replies or hardware identity')
finally:
    ip('link', 'delete', 'lantern0')
