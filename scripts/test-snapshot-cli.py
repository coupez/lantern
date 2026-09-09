#!/usr/bin/env python3
"""Verify the actual diff command with saved artifacts; no network access."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv)>1 else 'bin/lantern').resolve())
coverage = {'tcp_ports':[80,443], 'netbios': True}
before = {'schema':1,'target':'192.0.2.0/24','coverage':coverage,'devices':[
    {'ip':'192.0.2.1','names':['NAS.local.'], 'identity':{'name':'Office','model':'Model1'},
     'ports':[{'port':80},{'port':443}]}]}
after = copy.deepcopy(before)
after['coverage']['tcp_ports'] = [80]
after['devices'][0]['names'] = ['nas.local']
after['devices'][0]['identity']['model'] = 'Model2'
after['devices'][0]['ports'] = []

with tempfile.TemporaryDirectory(prefix='lantern-diff-') as directory:
    left, right = Path(directory)/'before.json', Path(directory)/'after.json'
    def compare(a,b):
        left.write_text(json.dumps(a))
        right.write_text(json.dumps(b))
        result = subprocess.run([binary,'diff',str(left),str(right)],capture_output=True,timeout=5,check=True)
        assert not result.stderr, result.stderr
        return json.loads(result.stdout)
    fields = {c['field']:c for c in compare(before,after)}
    assert set(fields) == {'coverage','ports','identity.model'}, fields
    assert fields['coverage']['type'] == 'scan' and fields['coverage']['ip'] == ''
    assert fields['ports']['before'] == ['80'] and not fields['ports'].get('after')
    assert fields['identity.model']['after'] == ['Model2']
    assert not compare(before,before)
    after['cancelled'] = True
    assert [c['field'] for c in compare(before,after)] == ['coverage']
    after['cancelled'] = False
    del before['coverage']
    del after['coverage']
    fields = {c['field']:c for c in compare(before,after)}
    assert fields['ports']['before'] == ['80','443'], fields
    partial = copy.deepcopy(after)
    partial['incomplete_methods'] = ['tcp']
    partial['devices'].append({'ip':'192.0.2.3'})
    original = copy.deepcopy(before)
    original['devices'].append({'ip':'192.0.2.2'})
    changes = compare(original,partial)
    assert not any(c['type'] == 'missing' or c.get('field') == 'ports' for c in changes), changes
    assert any(c['type'] == 'added' and c['ip'] == '192.0.2.3' for c in changes), changes
    fields = {c.get('field'):c for c in changes}
    assert fields['incomplete_methods']['after'] == ['tcp'] and fields['incomplete_methods']['type'] == 'scan', fields
    assert fields['identity.model']['after'] == ['Model2'], fields
    partial['incomplete_methods'] = ['multicast']
    fields = {c.get('field'):c for c in compare(original,partial)}
    assert 'identity.model' not in fields and fields['ports']['before'] == ['80','443'], fields
    recovered = copy.deepcopy(partial)
    del recovered['incomplete_methods']
    changes = compare(partial,recovered)
    assert len(changes) == 1 and changes[0]['field'] == 'incomplete_methods' and not changes[0].get('after'), changes

    for mac, role_name, identifier in [('00:00:5e:00:01:2a', 'VRRP/CARP', 42),
                                      ('00:00:5e:00:02:ff', 'VRRP IPv6', 255),
                                      ('00:00:0c:07:ac:00', 'HSRP v1', 0),
                                      ('00:00:0c:9f:ff:ff', 'HSRP v2 IPv4', 4095),
                                      ('00:05:73:a0:0f:ff', 'HSRP v2 IPv6', 4095)]:
        lookup = subprocess.run([binary, 'lookup', mac], capture_output=True, timeout=5, check=True)
        vendor = json.loads(lookup.stdout)
        role = vendor['address_role']
        assert role_name in role['name'] and role['identifier'] == identifier and role['references'], vendor
        assert vendor['name'] and not vendor['private'] and not vendor['multicast'], vendor
        snapshot = {'schema': 1, 'devices': [{'ip': '192.0.2.1', 'mac': mac, 'vendor': vendor}]}
        legacy = copy.deepcopy(snapshot)
        del legacy['devices'][0]['vendor']['address_role']
        assert not compare(snapshot, snapshot) and not compare(legacy, snapshot)
    for mac in ['02:00:5e:00:01:2a', '01:00:5e:00:01:2a', '00:00:5e:00:01:00']:
        lookup = subprocess.run([binary, 'lookup', mac], capture_output=True, timeout=5, check=True)
        assert 'address_role' not in json.loads(lookup.stdout)

    for devices in ([{}], [{'ip': None}], [{'ip': '::'}],
                    [{'ip': '192.0.2.1'}, {'ip': '192.0.2.1'}],
                    [{'ip': '2001:db8::1'}, {'ip': '2001:db8:0:0:0:0:0:1'}]):
        invalid = {'schema': 1, 'devices': devices}
        for a, b, bad_path in ((invalid, before, left), (before, invalid, right)):
            left.write_text(json.dumps(a))
            right.write_text(json.dumps(b))
            originals = [path.read_bytes() for path in (left, right)]
            result = subprocess.run([binary, 'diff', str(left), str(right)],
                                    capture_output=True, timeout=5)
            assert result.returncode == 1 and not result.stdout, result
            assert b'device' in result.stderr and str(bad_path).encode() in result.stderr, result.stderr
            assert [path.read_bytes() for path in (left, right)] == originals
print('PASS snapshot CLI: identity, coverage, cancellation, legacy files, partial recovery, invalid/duplicate devices, virtual MAC range lookup/metadata')
