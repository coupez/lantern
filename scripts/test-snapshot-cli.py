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
print('PASS snapshot CLI: structured identity changes, common-port coverage, cancellation, legacy files')
