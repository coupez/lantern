#!/usr/bin/env python3
"""Exercise the compiled CLI against an installed, unmodified Net-SNMP daemon.

Synthetic system fields and a pass_persist ENTITY-MIB fixture only. The daemon
handles BER, request/response IDs, community access, GET and GETBULK itself.
No host ports are published by the optional container invocation.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', nargs='?', default='bin/lantern')
    parser.add_argument('--snmpd', default=shutil.which('snmpd'))
    args = parser.parse_args()
    if not args.snmpd:
        parser.error('an installed Net-SNMP snmpd is required')
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix='lantern-snmp-interop-') as raw:
        root = Path(raw)
        # The independent daemon owns an ephemeral loopback port; a race between
        # reservation and startup fails the test instead of reaching another host.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        helper = root / 'entities.py'
        helper.write_text('''import sys
base = (1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1)
rows = {base+(4, 7): ("integer", "0"),
        base+(5, 7): ("integer", "3"),
        base+(6, 7): ("integer", "-1"),
        base+(12, 7): ("string", "Example"),
        base+(13, 7): ("string", "Switch 7")}
while True:
    command = sys.stdin.readline().strip()
    if not command: break
    if command == "PING":
        print("PONG", flush=True)
        continue
    raw = sys.stdin.readline().strip()
    oid = tuple(map(int, raw.strip(".").split(".")))
    key = oid if command == "get" and oid in rows else None
    if command == "getnext":
        key = next((key for key in sorted(rows) if key > oid), None)
    if key is None:
        print("NONE", flush=True)
    else:
        kind, value = rows[key]
        print("."+".".join(map(str, key)), kind, value, sep="\\n", flush=True)
''')
        community = 'lantern-synthetic-fixture'
        conf = root / 'snmpd.conf'
        conf.write_text(f'''agentAddress udp:127.0.0.1:{port}
rocommunity {community} 127.0.0.1
sysDescr Example inventory fixture
sysName Example switch
sysObjectID .1.3.6.1.4.1.8072.3.2.255
pass_persist .1.3.6.1.2.1.47.1.1.1.1 {sys.executable} {helper}
''')
        env = dict(os.environ, SNMP_PERSISTENT_DIR=str(root), MIBS='', LANTERN_TEST_SNMP_COMMUNITY=community)
        with (root / 'daemon.log').open('w+') as log:
            daemon = subprocess.Popen([args.snmpd, '-f', '-Lo', '-C', '-c', str(conf), '-p', str(root/'pid')], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                result = None
                for attempt in range(20):
                    if daemon.poll() is not None:
                        raise AssertionError(f'Net-SNMP daemon exited with {daemon.returncode}')
                    result = subprocess.run([binary, 'snmp', '127.0.0.1', '--port', str(port), '--community-env', 'LANTERN_TEST_SNMP_COMMUNITY', '--timeout', '1s', '--json'], env=env, capture_output=True, text=True, timeout=4)
                    if result.returncode == 0:
                        break
                    time.sleep(.1)
                assert result is not None and result.returncode == 0, result
                report = json.loads(result.stdout)
                assert report['schema'] == 1 and report['protocol'] == 'snmpv2c', report
                assert report['system'] == {'description': 'Example inventory fixture', 'object_id': '1.3.6.1.4.1.8072.3.2.255', 'name': 'Example switch'}, report
                assert report['entity_status'] == 'complete' and report['model'] == 'Switch 7' and report['manufacturer'] == 'Example', report
                assert report['model_oid'] == '1.3.6.1.2.1.47.1.1.1.1.13.7', report
                assert report['manufacturer_oid'] == '1.3.6.1.2.1.47.1.1.1.1.12.7', report
                assert report['entities'] == [{'index': 7, 'class': 3, 'parent': 0, 'manufacturer': 'Example', 'model': 'Switch 7'}], report
                assert community not in result.stdout + result.stderr, 'community leaked'
                assert not result.stderr, result.stderr
                plain = subprocess.run([binary, 'snmp', '--community-env', 'LANTERN_TEST_SNMP_COMMUNITY', '--port', str(port), '127.0.0.1'], env=env, capture_output=True, text=True, timeout=5)
                assert plain.returncode == 0 and 'Chassis model   Switch 7' in plain.stdout and not plain.stderr, plain
                assert community not in plain.stdout and '\x1b' not in plain.stdout, plain.stdout
                print('PASS independent Net-SNMP UDP/BER GET + GETBULK: system fields, chassis model/provenance, JSON/plain CLI, credential omission')
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=3)


if __name__ == '__main__':
    main()
