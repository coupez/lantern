#!/usr/bin/env python3
"""Verify a real 1-65535 CLI scan against a controlled loopback listener."""
import json
from pathlib import Path
import socket
import subprocess
import sys

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())
with socket.socket() as listener:
    # Prefer the boundary port; tolerate another local service already using it.
    try:
        listener.bind(('127.0.0.1', 65535))
    except OSError:
        listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    fixture_port = listener.getsockname()[1]
    result = subprocess.run([binary, 'scan', '127.0.0.1', '--ports', '1-65535', '--concurrency', '64',
                             '--timeout', '100ms', '--no-icmp', '--no-multicast', '--no-dns',
                             '--no-descriptions', '--json'], capture_output=True, text=True, timeout=60, check=True)
assert not result.stderr, result.stderr
report = json.loads(result.stdout)
assert report['coverage']['tcp_ports'] == list(range(1, 65536)), 'incomplete requested coverage'
assert report['probed'] == 1 and report['targets'] == 1 and len(report['devices']) == 1, report
assert not report.get('cancelled') and not report.get('error') and not report.get('warnings'), report
device = report['devices'][0]
assert device['ip'] == '127.0.0.1', device
ports = [p['port'] for p in device['ports']]
assert fixture_port in ports and ports == sorted(set(ports)), (fixture_port, ports)
# Other existing loopback services are allowed; they are also real observations.
assert 'tcp-open' in device['evidence'], device
print(f'PASS full-port CLI: 65,535 requested ports, controlled port {fixture_port} found, unique sorted observations, {report["duration_ms"]} ms')
