#!/usr/bin/env python3
"""Check the macOS live fixture's contract with simulated replies, not raw I/O."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ethernet_fixture', Path(__file__).with_name('test-ethernet-darwin.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/lantern').resolve())
sys.argv = sys.argv[:1]
real_run = subprocess.run


class FixtureTests(unittest.TestCase):
    def exercise(self, extra=None, unavailable=False, alter=None):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[1] == 'doctor':
                report = {'os': 'darwin', 'interface': 'en-test', 'networks': [{'address': '192.0.2.1'}],
                          'checks': [{'name': m, 'status': 'unavailable' if unavailable else 'available', 'detail': 'simulated prerequisite'} for m in ['arp', 'ndp']]}
            elif command[1] == 'diff':
                # Exercise the actual CLI syntax and snapshot loader/comparator.
                return real_run(command, **kwargs)
            else:
                self.assertEqual(command[1], 'scan')
                self.assertIn('--ports', command)
                self.assertEqual(command[command.index('--ports') + 1], 'none')
                for flag in ['--no-icmp', '--no-multicast', '--no-dns', '--no-descriptions', '--netbios=false']:
                    self.assertIn(flag, command)
                self.assertEqual(command[command.index('--interface') + 1], 'en-test')
                address = command[2]
                method = 'ndp' if ':' in address else 'arp'
                active = '--' + method + '=true' in command
                report = {'schema': 1, 'interface': 'en-test', 'target': address.split('%')[0] + ('/128' if method == 'ndp' else '/32'),
                          'targets': 1, 'probed': int(active),
                          'coverage': {'tcp_ports': [], **{k: active and k == method for k in
                                       ['arp', 'ndp', 'icmp', 'multicast', 'reverse_dns', 'descriptions', 'banners', 'netbios', 'all_hosts']}},
                          'devices': [{'ip': address, 'mac': '02:11:22:33:44:55', 'evidence': [method if active else 'neighbor-cache']}]}
                if alter:
                    alter(report)
                Path(command[command.index('--save') + 1]).write_text(json.dumps(report))
            return SimpleNamespace(returncode=0, stderr='', stdout=json.dumps(report))

        args = ['fixture', binary, '--interface', 'en-test'] + (extra if extra is not None else
                ['--ipv4', '192.0.2.2', '--mac4', '02:11:22:33:44:55', '--ipv6', 'fe80::2', '--mac6', '02:11:22:33:44:55'])
        with patch.object(sys, 'argv', args), patch.object(sys, 'platform', 'darwin'), \
             patch.object(fixture.socket, 'if_nametoindex', return_value=1), \
             patch.object(fixture.subprocess, 'run', side_effect=run), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = fixture.main()
        return code, calls

    def test_simulated_success_and_real_snapshot_diff(self):
        code, calls = self.exercise()
        self.assertEqual(code, 0)
        scans = [c for c in calls if c[1] == 'scan']
        self.assertEqual(len(scans), 6)
        self.assertEqual([c[2] for c in scans], ['192.0.2.2'] * 3 + ['fe80::2%en-test'] * 3)

    def test_denied_prerequisite_stops_before_probes(self):
        code, calls = self.exercise(unavailable=True)
        self.assertEqual(code, 2)
        self.assertEqual([c[1] for c in calls], ['doctor'])

    def test_check_only_never_scans(self):
        code, calls = self.exercise(extra=['--check-only'])
        self.assertEqual(code, 0)
        self.assertEqual([c[1] for c in calls], ['doctor'])

    def test_cached_wrong_or_extra_results_cannot_pass(self):
        for alter in [lambda r: r['devices'][0].update(evidence=['neighbor-cache']),
                      lambda r: r['devices'][0].update(mac='02:aa:bb:cc:dd:ee'),
                      lambda r: r['devices'][0].update(ip='192.0.2.3'),
                      lambda r: r.update(warnings=['raw discovery failed']),
                      lambda r: r.update(probed=0)]:
            with self.subTest(alter=alter), self.assertRaises(RuntimeError):
                self.exercise(alter=alter)

    def test_peer_validation(self):
        for extra in [[], ['--ipv4', '192.0.2.2'], ['--mac6', '02:11:22:33:44:55']]:
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as error:
                self.exercise(extra=extra)
            self.assertEqual(error.exception.code, 2)
        for address, family in [('192.0.2.0/24', 4), ('127.0.0.1', 4), ('224.0.0.1', 4), ('0.0.0.0', 4),
                                ('::1', 6), ('::ffff:192.0.2.2', 6), ('fe80::2%wrong', 6), ('192.0.2.2', 6)]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                fixture.peer_address(address, family, 'en-test')
        for mac in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:11:22:33:44:55', '02:11:22:33:44']:
            with self.subTest(mac=mac), self.assertRaises(ValueError):
                fixture.peer_mac(mac)


unittest.main()
