#!/usr/bin/env python3
"""Actual macOS CLI interoperability with native Bonjour, only on loopback.

Requires the system dns-sd publisher and access to mDNSResponder/local sockets.
Registers three synthetic services and removes them when the owned publishers
exit. Does not publish on a LAN interface or pair/control a device.
"""
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

if sys.platform != 'darwin':
    raise SystemExit('This fixture requires macOS dns-sd')
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())
roles = {'127.0.0.42': ('_matterc._udp', 'commissionable'),
         '127.0.0.43': ('_matterd._udp', 'commissioner'),
         '127.0.0.44': ('_matter._tcp', 'operational')}
publishers = []
records = []
with tempfile.TemporaryDirectory(prefix='lantern-matter-bonjour-') as directory:
    try:
        for ip, (service, role) in roles.items():
            instance = secrets.token_hex(8).upper()
            if role == 'operational':
                instance += '-' + secrets.token_hex(8).upper()
            host = 'lantern-matter-' + secrets.token_hex(4) + '.local.'
            log_path = Path(directory) / (role + '.log')
            with log_path.open('wb') as output:
                process = subprocess.Popen(['/usr/bin/dns-sd', '-i', 'lo0', '-t', '20', '-P',
                                            instance, service, 'local.', '5540', host, ip,
                                            'DN=Lantern Matter Fixture', 'VP=65521+32769', 'DT=256'],
                                           stdout=output, stderr=subprocess.STDOUT)
            publishers.append((process, log_path))
            records.append((host, ip))
        deadline = time.monotonic() + 6
        while True:
            logs = [(p, path.read_text()) for p, path in publishers]
            assert all(p.poll() is None for p, _ in logs), logs
            if all('Got a reply for service' in text and 'Name now registered and active' in text for _, text in logs):
                break
            assert time.monotonic() < deadline, logs
            time.sleep(.05)

        # Registration callbacks precede Bonjour's initial announcements. Query
        # each registered address through its native API before scanning UDP.
        for host, ip in records:
            ready = subprocess.run(['/usr/bin/dns-sd', '-i', 'lo0', '-t', '1', '-Q', host, 'A'],
                                   capture_output=True, timeout=3, check=True)
            assert ip.encode() in ready.stdout, ready.stdout

        snapshot = Path(directory) / 'report.json'
        # Include the publisher at 127.0.0.1: the collector deliberately rejects
        # off-target IPv4 senders, even when their A records name a target IP.
        command = [binary, 'scan', '127.0.0.0/26', '--interface', 'lo0', '--ports', 'none',
                   '--no-icmp', '--no-dns', '--no-descriptions', '--timeout', '1s', '--json']
        result = subprocess.run(command + ['--save', str(snapshot)], capture_output=True, timeout=8, check=True)
        assert not result.stderr, result.stderr
        report = json.loads(result.stdout)
        assert json.loads(snapshot.read_text()) == report
        devices = {d['ip']: d for d in report['devices']}
        assert set(roles) <= set(devices) <= set(roles) | {'127.0.0.1'}, set(devices)
        for ip, (_, role) in roles.items():
            d = devices[ip]
            id = d['identity']
            claims = {c['field']: c['value'] for c in id['claims']}
            assert claims['protocol'] == 'Matter' and claims['discovery_role'] == role, claims
            assert not d.get('ports') and not d.get('mac') and not id.get('model') and not id.get('manufacturer'), d
            if role == 'operational':
                assert len(claims) == 2 and not id.get('name') and d['kind'] == 'smart home device', d
            else:
                assert id['name'] == 'Lantern Matter Fixture' and d['kind'] == 'on/off light', d
                assert claims['matter_vendor_id'] == '65521' and claims['matter_product_id'] == '32769', claims
                assert claims['device_type_name'] == 'On/Off Light', claims
        disabled = subprocess.run(command + ['--no-multicast'], capture_output=True, timeout=8, check=True)
        assert all(d['ip'] == '127.0.0.1' and not d.get('advertisements')
                   for d in json.loads(disabled.stdout)['devices']), disabled.stdout
        print('PASS native Bonjour Matter: three discovery roles, name/type/ID claims, actual CLI snapshot, no inferred model/MAC/ports, multicast disable; loopback only')
    finally:
        for process, _ in publishers:
            process.terminate()
        for process, _ in publishers:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
