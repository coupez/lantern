#!/usr/bin/env python3
"""Compiled CLI against a synthetic loopback-only Ubiquiti UDP responder."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading

binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve()
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.1', 10001))
server.settimeout(5)
queries, errors = [], []

def tlv(tag, value):
    return bytes([tag]) + struct.pack('>H', len(value)) + value

def serve():
    try:
        for _ in range(2):
            query, peer = server.recvfrom(8193)
            assert query in (b'\x01\0\0\0', b'\x02\x08\0\0'), query.hex()
            assert peer[0] == '127.0.0.1'
            queries.append(query)
            version = query[0]
            # Extra address, MAC, username and SSID fields must be discarded.
            body = tlv(0x14 if version == 1 else 0x15, b'Fixture-v' + str(version).encode())
            body += tlv(0x0c, b'Fixture-platform') + tlv(0x03, b'Fixture-build')
            body += tlv(0x16, b'1.2.3') + tlv(0x0b, b'fixture-switch')
            for tag in (1, 2, 6, 7, 8, 9, 13):
                body += tlv(tag, b'discard-private-field')
            packet = bytes([version, 0 if version == 1 else 6]) + struct.pack('>H', len(body)) + body
            server.sendto(packet, peer)
    except BaseException as exc:
        errors.append(exc)

thread = threading.Thread(target=serve, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory(prefix='lantern-ubiquiti-') as directory:
        saved = Path(directory) / 'scan.json'
        process = subprocess.run([str(binary), 'scan', '127.0.0.1', '--ubiquiti', '--ports', 'none', '--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--timeout', '150ms', '--json', '--save', str(saved)], capture_output=True, text=True, timeout=10)
        assert process.returncode == 0, process.stderr
        result = json.loads(process.stdout)
        assert result == json.loads(saved.read_text())
        assert result['coverage']['ubiquiti']
        assert len(result['devices']) == 1
        device = result['devices'][0]
        assert device['ip'] == '127.0.0.1' and 'ubiquiti' in device['evidence']
        assert not device.get('ports')
        ads = [a for a in device['advertisements'] if a['protocol'] == 'ubiquiti']
        assert len(ads) == 2
        assert {a['properties']['protocol_version'] for a in ads} == {'1', '2'}
        claims = [c for c in device['identity']['claims'] if c['source'].startswith('ubiquiti:')]
        assert {c['value'] for c in claims if c['field'] == 'model'} == {'Fixture-v1', 'Fixture-v2'}
        assert all(c['reference'] for c in claims)
        assert {c['value'] for c in claims if c['field'] == 'name'} == {'fixture-switch'}
        assert 'discard-private-field' not in process.stdout
        assert {c['value'] for c in claims if c['field'] == 'platform'} == {'Fixture-platform'}
        # The local Mac model, if present, legitimately retains selection priority.
        # This fixture proves protocol claims, not the host's selected identity.
    thread.join(6)
    assert not thread.is_alive()
    if errors:
        raise errors[0]
    assert queries == [b'\x01\0\0\0', b'\x02\x08\0\0'], queries
    print('PASS Ubiquiti compiled CLI: exact probes, attributed/conflicting models, privacy-field discard, snapshot')
finally:
    server.close()
    thread.join(1)
