#!/usr/bin/env python3
"""Exercise the real CLI with independently encoded, synthetic capture files."""
import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'bin/lantern'


def dhcp4():
    b = bytearray(240)
    b[:3] = bytes([2, 1, 6])
    b[4:8] = bytes([1, 2, 3, 4])
    b[16:20] = bytes([192, 0, 2, 9])
    b[28:34] = bytes([2, 1, 2, 3, 4, 5])
    b[236:240] = bytes([99, 130, 83, 99])
    return b + bytes([53, 1, 2, 55, 3, 1, 3, 6, 60, 3, 0, 255, 27, 255])


def frame4():
    payload = dhcp4()
    udp = struct.pack('!HHHH', 67, 68, 8 + len(payload), 0) + payload
    ip = bytearray(20)
    ip[0], ip[8], ip[9] = 0x45, 61, 17
    ip[2:4] = struct.pack('!H', 20 + len(udp))
    ip[12:16], ip[16:20] = bytes([192, 0, 2, 1]), b'\xff' * 4
    return b'\xff' * 6 + bytes([2, 9, 8, 7, 6, 5]) + b'\x08\x00' + ip + udp


def frame6():
    payload = bytes([1, 1, 2, 3]) + struct.pack('!HHHH', 6, 4, 23, 24)
    udp = struct.pack('!HHHH', 546, 547, 8 + len(payload), 0) + payload
    ip = bytearray(40)
    ip[0], ip[6], ip[7] = 0x60, 17, 64
    ip[4:6] = struct.pack('!H', len(udp))
    ip[8:24] = bytes.fromhex('fe800000000000000000000000000001')
    ip[24:40] = bytes.fromhex('ff020000000000000000000000010002')
    return ip + udp


def classic(*packets):
    out = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for p in packets:
        out += struct.pack('<IIII', 1700000000, 123456, len(p), len(p)) + p
    return out


def block(endian, kind, body):
    n = 12 + len(body)
    assert n % 4 == 0
    return struct.pack(endian + 'II', kind, n) + body + struct.pack(endian + 'I', n)


def section(endian, link, packet):
    shb = block(endian, 0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1))
    # Nanosecond timestamp precision, with deliberately nonzero padding.
    options = struct.pack(endian + 'HH', 9, 1) + b'\x09\xab\xcd\xef' + b'\0' * 4
    idb = block(endian, 1, struct.pack(endian + 'HHI', link, 0, 65535) + options)
    ticks = 1700000000123456789
    data = packet + b'\xaa' * (-len(packet) % 4)
    epb = block(endian, 6, struct.pack(endian + 'IIIII', 0, ticks >> 32, ticks & 0xffffffff, len(packet), len(packet)) + data)
    return shb + idb + epb


class CaptureCLI(unittest.TestCase):
    def run_capture(self, data, *flags):
        with tempfile.TemporaryDirectory(prefix='lantern-dhcp-test-') as d:
            path = Path(d) / 'capture.pcap'
            path.write_bytes(data)
            return subprocess.run([str(BIN), 'observe', '--read', str(path), *flags], capture_output=True, text=True, timeout=10)

    def test_classic_evidence_and_binary_vendor(self):
        p = self.run_capture(classic(frame4()), '--json')
        self.assertEqual(p.returncode, 0, p.stderr)
        result = json.loads(p.stdout)
        self.assertFalse(result['summary']['incomplete'])
        row = result['observations'][0]
        self.assertEqual(row['source_ip'], '192.0.2.1')
        self.assertEqual(row['ethernet_source'], '02:09:08:07:06:05')
        self.assertEqual(row['ip_hop_limit'], 61)
        self.assertEqual(row['dhcp']['client_hardware_address'], '02:01:02:03:04:05')
        self.assertEqual(row['dhcp']['hints']['requested_options'], [1, 3, 6])
        self.assertNotIn('vendor_class', row['dhcp']['hints'])
        vendor = next(o for o in row['dhcp']['options'] if o['code'] == 60)
        self.assertEqual(base64.b64decode(vendor['data']), bytes([0, 255, 27]))
        self.assertNotIn('model', row['dhcp'])

    def test_mixed_sections_interfaces_and_nanosecond_time(self):
        data = section('<', 1, frame4()) + section('>', 229, frame6())
        p = self.run_capture(data, '--jsonl')
        self.assertEqual(p.returncode, 0, p.stderr)
        events = [json.loads(line) for line in p.stdout.splitlines()]
        self.assertEqual([e['type'] for e in events], ['observation', 'observation', 'complete'])
        rows = [e['observation'] for e in events[:2]]
        self.assertEqual([r['section'] for r in rows], [0, 1])
        self.assertEqual([r['interface'] for r in rows], [0, 0])
        self.assertEqual([r['dhcp']['version'] for r in rows], [4, 6])
        self.assertTrue(rows[0]['timestamp'].endswith('.123456789Z'), rows[0]['timestamp'])
        self.assertEqual(rows[1]['dhcp']['hints']['requested_options'], [23, 24])
        self.assertFalse(events[-1]['summary']['incomplete'])

    def test_partial_json_and_observation_limit(self):
        for data, flags in [(classic(frame4()) + b'\0', []), (classic(frame4(), frame4()), ['--limit', '1'])]:
            p = self.run_capture(data, '--json', *flags)
            self.assertNotEqual(p.returncode, 0)
            result = json.loads(p.stdout)
            self.assertTrue(result['summary']['incomplete'])
            self.assertEqual(len(result['observations']), 1)
            self.assertTrue(result['summary']['error'])

    def test_human_output_and_invalid_flags(self):
        p = self.run_capture(classic(frame4()), '--no-color')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('DHCPv4 Offer', p.stdout)
        self.assertIn('Client claim: 02:01:02:03:04:05', p.stdout)
        self.assertNotIn('\x1b', p.stdout)
        p = self.run_capture(classic(), '--json', '--jsonl')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, '')


if __name__ == '__main__':
    unittest.main()
