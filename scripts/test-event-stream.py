#!/usr/bin/env python3
"""Verify JSONL lifecycle using one controlled loopback TCP listener."""
import json
from pathlib import Path
import socket
import subprocess
import sys

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
assert {r['phase'] for r in rows if r['type'] == 'progress'} == {'discovery', 'ports', 'enrichment'}
assert updates[0]['phase'] == 'enrichment' and updates[0]['completed'] == updates[0]['total'] == 1
assert updates[0]['device'] == rows[-1]['report']['devices'][0]
assert [p['port'] for p in updates[0]['device']['ports']] == [port]
assert not initial[0]['device'].get('kind') and updates[0]['device']['kind'], 'initial snapshot changed during enrichment'
print('PASS JSONL lifecycle: initial discovery, TCP phases, complete device update, done, authoritative report')
