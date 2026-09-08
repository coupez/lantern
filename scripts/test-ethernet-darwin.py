#!/usr/bin/env python3
"""Verify raw macOS ARP/NDP against explicitly selected, known local peers.

No automatic target selection, privilege escalation, permission changes, cache
changes, or subnet scans. Each configured peer receives two single-address scans
with raw discovery enabled and one with all active discovery disabled.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def peer_address(value, version, interface):
    address = ipaddress.ip_address(value)
    if address.version != version or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError('peer must be a non-loopback unicast address of the requested family')
    if version == 4:
        if str(address) == '255.255.255.255':
            raise ValueError('broadcast is not a peer address')
    else:
        if address.ipv4_mapped:
            raise ValueError('use native IPv6 for NDP')
        if address.scope_id and address.scope_id != interface:
            raise ValueError('peer zone must match --interface')
        address = ipaddress.ip_address(str(address).split('%')[0])
        if address.is_link_local:
            return str(address) + '%' + interface
    return str(address)


def peer_mac(value):
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('expected MAC must contain six colon-separated octets')
    octets = bytes.fromhex(value.replace(':', ''))
    if octets[0] & 1 or not any(octets):
        raise ValueError('expected MAC must be a nonzero unicast Ethernet address')
    return value.lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', nargs='?', default='bin/lantern')
    parser.add_argument('--interface', required=True)
    parser.add_argument('--ipv4', help='one known on-link IPv4 peer address')
    parser.add_argument('--mac4', help='independently known Ethernet MAC of the IPv4 peer')
    parser.add_argument('--ipv6', help='one known on-link native IPv6 peer address')
    parser.add_argument('--mac6', help='independently known Ethernet MAC of the IPv6 peer')
    parser.add_argument('--check-only', action='store_true', help='only check local prerequisites; send no discovery packets')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('this fixture requires macOS')
    if not args.check_only and not (args.ipv4 or args.ipv6):
        parser.error('supply --ipv4/--mac4 and/or --ipv6/--mac6 for a known local peer')
    peers = []
    try:
        socket.if_nametoindex(args.interface)
        for version, address, mac in [(4, args.ipv4, args.mac4), (6, args.ipv6, args.mac6)]:
            if bool(address) != bool(mac):
                raise ValueError(f'--ipv{version} and --mac{version} must be supplied together')
            if address:
                peers.append(('arp' if version == 4 else 'ndp', peer_address(address, version, args.interface), peer_mac(mac)))
    except (ValueError, OSError) as error:
        parser.error(str(error))
    binary = str(Path(args.binary).resolve(strict=True))

    def run(*flags):
        result = subprocess.run([binary, *flags], capture_output=True, text=True, timeout=15)
        require(result.returncode == 0 and not result.stderr, f'CLI failed: {result.returncode}; {result.stderr!r}')
        return json.loads(result.stdout)

    doctor = run('doctor', '--interface', args.interface, '--json')
    require(doctor['os'] == 'darwin' and doctor['interface'] == args.interface, 'wrong platform or interface in doctor')
    checks = {c['name']: c for c in doctor['checks']}
    methods = [p[0] for p in peers] or ['arp', 'ndp']
    # Check every requested capability before any peer receives a probe.
    unavailable = [method for method in methods if checks[method]['status'] != 'available']
    for method in methods:
        print(f"{method}: {checks[method]['status']} ({checks[method]['detail']})")
    if unavailable:
        print('UNVERIFIED: raw discovery prerequisites are unavailable; no peer probes sent.', file=sys.stderr)
        return 2
    if args.check_only:
        print('Local prerequisites available; live peer discovery remains unverified. No probes sent.')
        return 0

    local_addresses = {str(ipaddress.ip_address(n['address'].split('%')[0])) for n in doctor['networks']}
    require(all(address.split('%')[0] not in local_addresses for _, address, _ in peers), 'select a peer, not an address of this Mac')
    with tempfile.TemporaryDirectory(prefix='lantern-darwin-ethernet-') as directory:
        for method, address, mac in peers:
            base = ['scan', address, '--interface', args.interface, '--ports', 'none', '--no-icmp',
                    '--no-multicast', '--no-dns', '--no-descriptions', '--netbios=false', '--timeout', '2s', '--json']

            def scan(enabled, label):
                path = Path(directory) / f'{method}-{label}.json'
                report = run(*base, '--arp=' + str(enabled and method == 'arp').lower(),
                             '--ndp=' + str(enabled and method == 'ndp').lower(), '--save', str(path))
                require(report == json.loads(path.read_text()), 'saved snapshot differs from CLI report')
                require(not report.get('error') and not report.get('cancelled') and not report.get('warnings')
                        and not report.get('incomplete_methods'), f'incomplete scan: {report!r}')
                require(report['interface'] == args.interface and report['targets'] == 1, 'scan escaped the selected peer/interface')
                coverage = report['coverage']
                require(not coverage['tcp_ports'] and all(not coverage[k] for k in
                        ['icmp', 'multicast', 'reverse_dns', 'descriptions', 'banners', 'netbios', 'all_hosts']), 'unexpected active discovery')
                require(coverage[method] == enabled and not coverage['ndp' if method == 'arp' else 'arp'], 'wrong raw discovery coverage')
                for device in report['devices']:
                    require(device['ip'] == address and not device.get('ports'), 'unexpected device or TCP observation')
                    require(set(device.get('evidence', [])) <= {method, 'neighbor-cache'}, 'unrelated response evidence')
                    require(not device.get('advertisements'), 'unexpected protocol advertisements')
                if enabled:
                    require(report['probed'] == 1 and len(report['devices']) == 1, 'peer did not answer a direct probe')
                    device = report['devices'][0]
                    require(method in device['evidence'] and device['mac'].lower() == mac, 'fresh response/expected MAC not established')
                else:
                    require(report['probed'] == 0 and all(method not in d.get('evidence', []) for d in report['devices']), 'disabled method still probed/reported a reply')
                return path

            first = scan(True, 'first')
            second = scan(True, 'second')
            require(run('diff', str(first), str(second)) == [], 'repeated raw observations produced a diff')
            scan(False, 'disabled')
            print(f'PASS {method}: expected peer MAC from fresh replies, single-address scope, repeated snapshot/diff, disabled method')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
