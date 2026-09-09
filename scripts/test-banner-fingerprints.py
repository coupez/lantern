#!/usr/bin/env python3
"""Actual CLI banner recognition on owned HTTP/HTTPS loopback listeners; no LAN traffic."""
import copy
from contextlib import ExitStack
import csv
import io
import json
import os
import selectors
import signal
import time
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

# Public test-only key and self-signed certificate for fixture.invalid; never credentials.
# Certificate validity/name are intentionally irrelevant to inventory observations.
TLS_CERT = '-----BEGIN CERTIFICATE-----\nMIIBiTCCAS+gAwIBAgIUS9RzMIuJ3frYyDazrSGqp1mer6QwCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPZml4dHVyZS5pbnZhbGlkMB4XDTI2MDkwOTAwMzA0MloXDTI2\nMDkxMDAwMzA0MlowGjEYMBYGA1UEAwwPZml4dHVyZS5pbnZhbGlkMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAE4YqdGbdNuQnDc8FA3B+T25Ox4UQoVdTAy1reC31P\nL5Yc966tA1yKK65I4wItM4km+4BZWqUWO1TwJ6u3nGDSwqNTMFEwHQYDVR0OBBYE\nFAP4LUaMRT62c7iYkTWf4tB960exMB8GA1UdIwQYMBaAFAP4LUaMRT62c7iYkTWf\n4tB960exMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAMuZZvMe\nOZgs3xe/ioWO6ttKzK2ZEP/YykEEJnJjS369AiBLRI+88oSQR/6a+Ww3k2EF0HpE\npVHgNq6JPv9B2wrCcg==\n-----END CERTIFICATE-----\n'
TLS_KEY = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYXi+9adoT9atMlDx\n0QkKXOT8+YsQ2+FR8ANd0cTeBVyhRANCAAThip0Zt025CcNzwUDcH5Pbk7HhRChV\n1MDLWt4LfU8vlhz3rq0DXIorrkjjAi0ziSb7gFlapRY7VPAnq7ecYNLC\n-----END PRIVATE KEY-----\n'

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())
def run(*args):
    result = subprocess.run([binary, *args], check=True, capture_output=True, text=True, timeout=15)
    if "--details" not in args:
        assert not result.stderr, result.stderr
    return result.stdout

assert '946' in run('fingerprint')
assert json.loads(run('fingerprint', 'ssh', 'OpenSSH_9.9'))['fields']['service.product'] == 'OpenSSH'
assert json.loads(run('fingerprint', 'http', 'Eltex TAU-72'))['fields']['os.product'] == 'TAU-72 Firmware'
assert json.loads(run('fingerprint', 'http', 'LanternUnknownServer_2026')) is None
assert json.loads(run('fingerprint', 'sources'))['license'] == 'BSD-2-Clause'
def watch_service_change(base, reply, port):
    reply[0] = b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.65\r\n\r\n'
    process = subprocess.Popen([binary, 'watch', *base[1:], '--jsonl', '--interval', '1s'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pending = b''; reports = []; changes = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 15
            while changes is None and time.monotonic() < deadline:
                for key, _ in selector.select(.2):
                    data = os.read(key.fd, 65536)
                    assert data, 'watch exited before reporting changes'
                    pending += data
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        event = json.loads(line)
                        if event.get('report') and event['type'] in ('done', 'report'):
                            reports.append(event['report'])
                            reply[0] = b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.66\r\n\r\n'
                        if event['type'] == 'changes':
                            changes = event['changes']
            assert changes is not None and len(reports) == 2, (changes, len(reports))
            assert len(changes) == 1, changes
            change = changes[0]
            assert change['port'] == port and change['field'] == 'service.version', change
            assert change['before'] == ['2.4.65'] and change['after'] == ['2.4.66'], change
            process.send_signal(signal.SIGINT)
            _, error = process.communicate(timeout=5)
            assert process.returncode == 0 and not error, (process.returncode, error)
            return reports, changes
    finally:
        if process.poll() is None:
            process.kill(); process.communicate(timeout=5)

for service in ['http', 'https']:
    for family, host in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
        with tempfile.TemporaryDirectory(prefix='lantern-banner-') as directory, socket.socket(family) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            for port in ([3000, 5000, 8008, 8080, 9000] if service == 'http' else [8443, 443]):
                try:
                    listener.bind((host, port))
                    break
                except OSError:
                    continue
            else:
                raise AssertionError(f'No supported {service} fixture port available')
            authority = f'[{host}]:{port}' if family == socket.AF_INET6 else f'{host}:{port}'
            tls_context = None
            if service == 'https':
                cert_path, key_path = Path(directory)/'cert.pem', Path(directory)/'key.pem'
                cert_path.write_text(TLS_CERT)
                key_path.write_text(TLS_KEY)
                tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls_context.load_cert_chain(cert_path, key_path)
                tls_context.set_alpn_protocols(['h2', 'http/1.1'])
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
                        with ExitStack() as sockets:
                            sockets.enter_context(conn)
                            conn.settimeout(3)
                            # TCP reachability probes connect and close without an application request.
                            if not conn.recv(1, socket.MSG_PEEK):
                                continue
                            if tls_context:
                                conn = sockets.enter_context(tls_context.wrap_socket(conn, server_side=True))
                                assert conn.selected_alpn_protocol() == 'http/1.1'
                            request = b''
                            while b'\r\n\r\n' not in request and len(request) < 4096:
                                chunk = conn.recv(4096-len(request))
                                if not chunk:
                                    break
                                request += chunk
                            if request:
                                assert request == f'HEAD / HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n'.encode(), request
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
                assert observation['service'] == service, observation
                match = observation['fingerprint']
                assert observation['banner'] == 'Apache/2.4.65' and match['input'] == observation['banner']
                assert match['fields']['service.product'] == 'HTTPD' and match['fields']['service.version'] == '2.4.65'
                assert match['catalog'] == 'Rapid7 Recog' and '#L' in match['reference']
                assert not device.get('identity') and not device.get('mac') and not device['vendor'].get('name'), device
                assert len(requests) == 1, requests
                csv_row = list(csv.DictReader(io.StringIO(run(*base, '--csv'))))[0]
                assert csv_row['service_fingerprints'] == f'{port}/{service}: Apache HTTPD 2.4.65'
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
                watched, changes = watch_service_change(base, reply, port)
                left, right = Path(directory)/'watch-before.json', Path(directory)/'watch-after.json'
                left.write_text(json.dumps(watched[0])); right.write_text(json.dumps(watched[1]))
                assert json.loads(run('diff', str(left), str(right))) == changes
                updated_catalog = copy.deepcopy(watched[1])
                updated_catalog['devices'][0]['ports'][0]['fingerprint']['fields']['service.version'] = 'catalog reinterpretation'
                left.write_text(json.dumps(updated_catalog))
                assert json.loads(run('diff', str(left), str(right))) == []
            finally:
                stop.set()
                worker.join(5)
                assert not worker.is_alive() and not failures, failures
        print(f'PASS {host}: actual {service.upper()} field recognition, JSONL/snapshot ownership, CSV/details, disable flag, tainted-input exclusion, legacy diff, live watch service upgrade and catalog-only suppression')
print('PASS offline SSH/HTTP lookup and source provenance')
