#!/usr/bin/env python3
"""Verify JSONL lifecycle using one controlled loopback TCP listener."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    result = subprocess.run([binary, 'scan', '127.0.0.1', '--ports', str(port), '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--jsonl'], capture_output=True, text=True, timeout=10, check=True)
assert not result.stderr, result.stderr
rows = [json.loads(line) for line in result.stdout.splitlines()]
assert rows[-1]['type'] == 'report' and rows[-2]['type'] == 'done', rows
initial = [r for r in rows if r['type'] == 'device']
updates = [r for r in rows if r['type'] == 'device_update']
assert len(initial) == len(updates) == 1, rows
assert rows.index(initial[0]) < rows.index(updates[0]) < len(rows)-2
assert {r['phase'] for r in rows if r['type'] == 'progress'} == {'ports', 'enrichment'}
tcp_progress = [r for r in rows if r['type'] == 'progress' and r['phase'] == 'ports']
assert tcp_progress[-1]['completed'] == tcp_progress[-1]['total'] == len({port, 80, 443, 22})
assert updates[0]['phase'] == 'enrichment' and updates[0]['completed'] == updates[0]['total'] == 1
assert updates[0]['device'] == rows[-1]['report']['devices'][0]
assert [p['port'] for p in updates[0]['device']['ports']] == [port]
assert not initial[0]['device'].get('kind') and updates[0]['device']['kind'], 'initial snapshot changed during enrichment'
print('PASS JSONL lifecycle: initial discovery, TCP phases, complete device update, done, authoritative report')

# No reader exists before the CLI starts. Go normally terminates on SIGPIPE for
# stdout; Lantern must instead cancel, join the scanner, and finish --save.
with tempfile.TemporaryDirectory(prefix='lantern-broken-pipe-') as tmp:
    snapshot = Path(tmp) / 'partial.json'
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        result = subprocess.run([binary, 'scan', '127.0.0.1', '--ports', '1-65535',
                                 '--concurrency', '1', '--no-icmp', '--no-multicast',
                                 '--no-dns', '--no-descriptions', '--jsonl', '--save', str(snapshot)],
                                stdout=write_fd, stderr=subprocess.PIPE, text=True, timeout=5)
    finally:
        os.close(write_fd)
    assert result.returncode == 1 and 'broken pipe' in result.stderr.lower(), result
    saved = json.loads(snapshot.read_text())
    assert saved['cancelled'] and saved['devices'], saved
    assert not saved.get('error'), saved
print('PASS broken JSONL pipe: graceful error exit, cancelled scan, partial snapshot preserved')

# Interrupt an actual HTTP banner read with a 30-second deadline. The CLI must
# close its connection and publish/save the partial aggregate without waiting.
with tempfile.TemporaryDirectory(prefix='lantern-interrupt-') as tmp, socket.socket() as listener:
    for port in [3000, 5000, 8008, 8080, 9000]:
        try:
            listener.bind(('127.0.0.1', port))
            break
        except OSError:
            continue
    else:
        raise AssertionError('no known HTTP fixture port available')
    listener.listen(8)
    listener.settimeout(5)
    request_seen = threading.Event()
    closed = threading.Event()
    failures = []

    def serve():
        try:
            # First connection is the open-port probe; next is enrichment.
            with listener.accept()[0] as probe:
                probe.settimeout(5)
                assert probe.recv(4096) == b''
            with listener.accept()[0] as banner:
                banner.settimeout(5)
                request = b''
                while b'\r\n\r\n' not in request:
                    chunk = banner.recv(4096)
                    assert chunk, request
                    request += chunk
                request_seen.set()
                assert banner.recv(4096) == b'', 'cancelled banner socket stayed open'
                closed.set()
        except Exception as exc:
            failures.append(exc)
            request_seen.set()

    worker = threading.Thread(target=serve)
    worker.start()
    snapshot = Path(tmp) / 'partial.json'
    process = subprocess.Popen([binary, 'scan', '127.0.0.1', '--ports', str(port), '--banners',
                                '--timeout', '30s', '--no-icmp', '--no-multicast', '--no-dns',
                                '--no-descriptions', '--jsonl', '--save', str(snapshot)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert request_seen.wait(5) and not failures, failures
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0 and not stderr, (process.returncode, stderr)
        rows = [json.loads(line) for line in stdout.splitlines()]
        assert rows[-1]['type'] == 'report' and rows[-2]['type'] == 'done', rows
        saved = json.loads(snapshot.read_text())
        assert saved == rows[-1]['report'] and saved['cancelled'], saved
        assert [p['port'] for p in saved['devices'][0]['ports']] == [port], saved
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        worker.join(6)
    assert not worker.is_alive() and closed.is_set() and not failures, failures
print('PASS SIGINT during banner read: socket closed, workers joined, partial JSONL report and snapshot agree')
