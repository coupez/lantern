#!/usr/bin/env python3
"""Actual CLI banner recognition on owned HTTP loopback listeners; no LAN traffic."""
import copy
import csv
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())
def run(*args):
    result = subprocess.run([binary, *args], check=True, capture_output=True, text=True, timeout=15)
    if "--details" not in args:
        assert not result.stderr, result.stderr
    return result.stdout

assert '608' in run('fingerprint')
assert json.loads(run('fingerprint', 'ssh', 'OpenSSH_9.9'))['fields']['service.product'] == 'OpenSSH'
assert json.loads(run('fingerprint', 'http', 'Eltex TAU-72'))['fields']['os.product'] == 'TAU-72 Firmware'
assert json.loads(run('fingerprint', 'http', 'LanternUnknownServer_2026')) is None
assert json.loads(run('fingerprint', 'sources'))['license'] == 'BSD-2-Clause'
for family, host in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
    with tempfile.TemporaryDirectory(prefix='lantern-banner-') as directory, socket.socket(family) as listener:
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        for port in [3000, 5000, 8008, 8080, 9000]:
            try:
                listener.bind((host, port))
                break
            except OSError:
                continue
        else:
            raise AssertionError('No supported HTTP fixture port available')
        listener.listen(8)
        listener.settimeout(.2)
        stop = threading.Event()
        failures, requests = [], []
        reply = [b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\nContent-Length: 0\r\n\r\n']
        def serve():
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(3)
                        request = b''
                        while b'\r\n\r\n' not in request and len(request) < 4096:
                            chunk = conn.recv(4096-len(request))
                            if not chunk:
                                break
                            request += chunk
                        if request:
                            assert request.startswith(b'HEAD / HTTP/1.0\r\n'), request
                            requests.append(request)
                            conn.sendall(reply[0])
            except Exception as err:
                failures.append(repr(err))
        worker = threading.Thread(target=serve)
        worker.start()
        base = ['scan', host, '--ports', str(port), '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--banners', '--timeout', '1s']
        try:
            snapshot = Path(directory)/'saved.json'
            events = [json.loads(line) for line in run(*base, '--jsonl', '--save', str(snapshot)).splitlines()]
            report = events[-1]['report']
            assert json.loads(snapshot.read_text()) == report
            device = report['devices'][0]
            assert [e['device'] for e in events if e['type'] == 'device_update'] == [device]
            observation = device['ports'][0]
            match = observation['fingerprint']
            assert observation['banner'] == 'Apache/2.4.65' and match['input'] == observation['banner']
            assert match['fields']['service.product'] == 'HTTPD' and match['fields']['service.version'] == '2.4.65'
            assert match['catalog'] == 'Rapid7 Recog' and '#L' in match['reference']
            assert not device.get('identity') and not device.get('mac') and not device['vendor'].get('name'), device
            assert len(requests) == 1, requests
            csv_row = list(csv.DictReader(io.StringIO(run(*base, '--csv'))))[0]
            assert csv_row['service_fingerprints'] == f'{port}/http: Apache HTTPD 2.4.65'
            assert not csv_row['manufacturer'] and not csv_row['model']
            plain = run(*base, '--details', '--no-color')
            assert 'Catalog · TCP' in plain and 'service.product = HTTPD' in plain and match['reference'] in plain
            before = len(requests)
            disabled = json.loads(run(*base, '--banners=false', '--json'))['devices'][0]['ports'][0]
            assert not disabled.get('banner') and not disabled.get('fingerprint') and len(requests) == before
            reply[0] = b'HTTP/1.1 200 OK\r\nServer: Apa\x1bche/2.4.65\r\n\r\n'
            tainted = json.loads(run(*base, '--json'))['devices'][0]['ports'][0]
            assert tainted['banner'] == 'Apache/2.4.65' and not tainted.get('fingerprint'), tainted
            reply[0] = 'HTTP/1.1 200 OK\r\nſerver: Apache/2.4.65\r\n\r\n'.encode()
            non_ascii = json.loads(run(*base, '--json'))['devices'][0]['ports'][0]
            assert not non_ascii.get('fingerprint'), non_ascii
            legacy = copy.deepcopy(report)
            del legacy['devices'][0]['ports'][0]['fingerprint']
            old = Path(directory)/'legacy.json'; old.write_text(json.dumps(legacy))
            assert json.loads(run('diff', str(old), str(snapshot))) == []
        finally:
            stop.set()
            worker.join(5)
            assert not worker.is_alive() and not failures, failures
    print(f'PASS {host}: actual HTTP field recognition, JSONL/snapshot ownership, CSV/details, disable flag, tainted-input exclusion, legacy diff')
print('PASS offline SSH/HTTP lookup and source provenance')
