#!/usr/bin/env python3
"""Solicit real Linux kernel neighbors over an isolated Ethernet veth pair."""
import json
from pathlib import Path
import subprocess
import sys
import time

if not Path('/.dockerenv').exists():
    raise SystemExit('Requires the isolated test container with CAP_NET_ADMIN and CAP_NET_RAW.')
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/lantern').resolve())


def ip(*args):
    return subprocess.run(['ip', *args], check=True, capture_output=True, text=True, timeout=5)


ip('link', 'add', 'ndp0', 'type', 'veth', 'peer', 'name', 'ndp1')
try:
    for iface, suffix in [('ndp0', 1), ('ndp1', 2)]:
        ip('link', 'set', iface, 'address', f'02:11:22:33:44:{suffix:02x}')
        ip('link', 'set', iface, 'up')
        ip('-6', 'addr', 'add', f'fd77:123::{suffix}/64', 'dev', iface, 'nodad')
        ip('-6', 'addr', 'add', f'fe80::{suffix}/64', 'dev', iface, 'nodad')

    def scan(target, interface='ndp0', timeout='2s'):
        result = subprocess.run([binary, 'scan', target, '--interface', interface, '--ndp', '--ports', 'none',
                                 '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions',
                                 '--timeout', timeout, '--json'], capture_output=True, text=True, timeout=8, check=True)
        assert not result.stderr, result.stderr
        report = json.loads(result.stdout)
        assert not report.get('warnings') and report['coverage']['ndp'], report
        return report

    if '--without-raw' in sys.argv[2:]:
        ip('-6', 'neigh', 'replace', 'fd77:123::2', 'lladdr', '02:aa:bb:cc:dd:ee', 'dev', 'ndp0', 'nud', 'permanent')
        result = subprocess.run([binary, 'scan', 'fd77:123::2', '--interface', 'ndp0', '--ndp', '--ports', 'none',
                                 '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--json'],
                                capture_output=True, text=True, timeout=5, check=True)
        report = json.loads(result.stdout)
        assert report['probed'] == 0 and len(report['devices']) == 1, report
        assert report['devices'][0]['evidence'] == ['neighbor-cache'], report
        assert any('NDP unavailable' in w and 'operation not permitted' in w.lower() for w in report['warnings']), report
        doctor = subprocess.run([binary, 'doctor', '--interface', 'ndp0', '--json'], capture_output=True, text=True, timeout=5, check=True)
        checks = {c['name']: c for c in json.loads(doctor.stdout)['checks']}
        assert checks['target6']['status'] == 'available' and checks['ndp']['status'] == 'unavailable', checks
        assert 'operation not permitted' in checks['ndp']['detail'].lower(), checks['ndp']
        print('PASS NDP without raw capability: warning, cached-only fallback, no probes, doctor reports permission denial')
    else:
        for target in ['fd77:123::2', 'fe80::2']:
            # Supply a deliberately wrong cached mapping. Fresh solicited NDP must
            # win without relying on TCP, echo replies, or that cache entry.
            ip('-6', 'neigh', 'replace', target, 'lladdr', '02:aa:bb:cc:dd:ee', 'dev', 'ndp0', 'nud', 'permanent')
            start = time.monotonic()
            report = scan(target)
            assert time.monotonic() - start < 1.5, 'all replies received but waited for the 2s deadline'
            assert report['interface'] == 'ndp0' and report['probed'] == 1 and len(report['devices']) == 1, report
            device = report['devices'][0]
            assert device['ip'] == target + ('%ndp0' if target.startswith('fe80:') else ''), device
            assert device['mac'] == '02:11:22:33:44:02' and 'ndp' in device['evidence'], device
            assert not device.get('ports') and 'local-interface' not in device['evidence'], device

        report = scan('fd77:123::/64', timeout='100ms')
        by_ip = {d['ip']: d for d in report['devices']}
        assert report['address_mode'] == 'discovered' and report['targets'] == 2 and report['probed'] == 1, report
        assert 'ndp' in by_ip['fd77:123::2']['evidence'], report

        report = scan('fd77:123::/126', timeout='100ms')
        by_ip = {d['ip']: d for d in report['devices']}
        assert report['targets'] == 4 and report['probed'] == 3, report
        assert 'ndp' in by_ip['fd77:123::2']['evidence'] and 'local-interface' in by_ip['fd77:123::1']['evidence'], report
        # Explicit finite targets outside every configured prefix must not emit NS.
        report = scan('fd99::2', timeout='100ms')
        assert report['probed'] == 0 and not report['devices'], report
        doctor = subprocess.run([binary, 'doctor', '--interface', 'ndp0', '--json'], capture_output=True, text=True, timeout=5, check=True)
        ndp = next(c for c in json.loads(doctor.stdout)['checks'] if c['name'] == 'ndp')
        assert ndp['status'] == 'available', ndp
        print('PASS direct NDP: real kernel global/link-local replies, fresh MAC precedence, scoped evidence, early completion, finite/sparse ranges, off-link exclusion, doctor')

finally:
    ip('link', 'delete', 'ndp0')
