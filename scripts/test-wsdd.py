#!/usr/bin/env python3
"""Exercise the actual CLI against Debian's independent wsdd daemon."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

if not Path('/.dockerenv').exists():
    raise SystemExit('Requires the isolated Linux test container; --ipv6 also needs CAP_NET_ADMIN.')
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/lantern').resolve())
ipv6 = '--ipv6' in sys.argv[2:]
identifier = '57b787e9-436b-40f7-990b-534ba5aa6be0'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=8, **kwargs)


created_link = False
try:
    if ipv6:
        run('ip', 'link', 'add', 'wsd0', 'type', 'veth', 'peer', 'name', 'wsd1')
        created_link = True
        for interface, suffix in [('wsd0', '10'), ('wsd1', '11')]:
            run('ip', 'link', 'set', interface, 'addrgenmode', 'none')
            run('ip', 'link', 'set', interface, 'up')
            run('ip', '-6', 'addr', 'add', f'fe80::{suffix}/64', 'dev', interface, 'nodad')
        interface, address = 'wsd0', 'fe80::10%wsd0'
    else:
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default').stdout)
        interface = routes[0]['dev']
        links = json.loads(run('ip', '-j', '-4', 'address', 'show', 'dev', interface).stdout)
        address = next(a['local'] for a in links[0]['addr_info'] if a['family'] == 'inet')

    with tempfile.TemporaryDirectory(prefix='lantern-wsdd-') as tmp:
        tmp = Path(tmp)
        with (tmp / 'wsdd.log').open('w') as log:
            child = subprocess.Popen(['wsdd', '-i', interface, '-6' if ipv6 else '-4', '-t',
                                      '-U', identifier, '-n', 'LANTERN-WSDD', '-w', 'LANTERN-LAB', '-v'],
                                     stdout=log, stderr=subprocess.STDOUT)
            try:
                def scan(*flags):
                    assert child.poll() is None, 'wsdd stopped unexpectedly'
                    result = run(binary, 'scan', address, '--interface', interface,
                                 '--ports', 'none', '--no-icmp', '--no-dns', '--no-descriptions',
                                 '--timeout', '300ms', '--json', *flags)
                    assert not result.stderr, result.stderr
                    report = json.loads(result.stdout)
                    assert not report.get('warnings') and not report.get('incomplete_methods'), report
                    return report

                def observed(report):
                    ads = [(device, ad) for device in report['devices']
                           for ad in device.get('advertisements', []) if ad['protocol'] == 'ws-discovery']
                    assert len(ads) == 1, report
                    device, ad = ads[0]
                    assert device['ip'] == address and 'ws-discovery' in device['evidence'], device
                    assert ad['instance'] == 'urn:uuid:' + identifier and ad['service'] == 'probe-match', ad
                    assert ad['properties']['discovery_namespace'] == 'http://schemas.xmlsoap.org/ws/2005/04/discovery', ad
                    assert set(ad['properties']['types'].split()) == {
                        '{http://schemas.microsoft.com/windows/pub/2005/07}Computer',
                        '{http://schemas.xmlsoap.org/ws/2006/02/devprof}Device'}, ad
                    assert ad['properties']['message_id'], ad
                    assert not device.get('ports'), 'advertised endpoint became a verified TCP port'
                    assert not device.get('identity'), 'hostname/model inferred without metadata or ONVIF scopes'
                    return ad

                # Each retry verifies that the owned daemon remains alive. Probe
                # retries normally cover startup; cap startup readiness at 3 scans.
                for attempt in range(3):
                    first = scan()
                    try:
                        first_ad = observed(first)
                        break
                    except AssertionError:
                        if attempt == 2:
                            raise
                second = scan()
                second_ad = observed(second)
                assert first_ad['properties']['message_id'] != second_ad['properties']['message_id'], 'did not get a fresh response'
                for name, report in [('first', first), ('second', second)]:
                    (tmp / f'{name}.json').write_text(json.dumps(report))
                diff = run(binary, 'diff', str(tmp / 'first.json'), str(tmp / 'second.json'))
                assert json.loads(diff.stdout) == [], diff.stdout
                disabled = scan('--no-multicast')
                assert not disabled['coverage']['multicast'], disabled
                assert all('ws-discovery' not in d['evidence'] for d in disabled['devices']), disabled
                assert all(a['protocol'] != 'ws-discovery' for d in disabled['devices'] for a in d.get('advertisements', [])), disabled
                print(run('dpkg-query', '-W', 'wsdd').stdout.strip())
                print(json.dumps(first, indent=2))
                print(f'PASS wsdd interoperability ({"IPv6" if ipv6 else "IPv4"}): real ProbeMatches, scoped sender, stable endpoint, fresh replies, no invented ports/identity, unchanged diff, multicast disable')
            except BaseException:
                log.flush()
                print((tmp / 'wsdd.log').read_text(), file=sys.stderr)
                raise
            finally:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
finally:
    if created_link:
        run('ip', 'link', 'delete', 'wsd0')
