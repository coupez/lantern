#!/usr/bin/env python3
"""Actual FTP/SMTP CLI fixtures on owned loopback ports 21/25; no commands sent.

Requires permission to bind these ports, which must be unused. Linux integration
runs this in the isolated test container; normal unit tests use net.Pipe.
"""
import csv
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

binary = str(Path(sys.argv[1] if len(sys.argv)>1 else 'bin/lantern').resolve())
def run(*args):
    result = subprocess.run([binary,*args],capture_output=True,text=True,check=True,timeout=15)
    if '--details' not in args:
        assert not result.stderr, result.stderr
    return result.stdout

ftp = 'ET000400CEA560 Lexmark T640 FTP Server NS.NP.N219 ready.'
smtp = 'foo.bar ESMTP Postfix (3.1.4)'
for service,port,text,product in [('ftp',21,ftp,'T640'),('smtp',25,smtp,'Postfix')]:
    offline = json.loads(run('fingerprint',service,text))
    assert offline and offline['field'] == service+'.banner'
    for family,host in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
        with tempfile.TemporaryDirectory(prefix='lantern-greeting-') as directory, socket.socket(family) as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            listener.bind((host,port))
            listener.listen(8); listener.settimeout(.1)
            stop = threading.Event(); failures=[]; connections=[]
            # FTP exercises an unprefixed middle line; SMTP prefixes each line.
            value = ('Notice\r\n'+text if service=='ftp' else text+'\r\nNotice')+'\r\nReady'
            wire = '220-Notice\r\n'+text+'\r\n220 Ready\r\n' if service=='ftp' else '220-'+text+'\r\n220-Notice\r\n220 Ready\r\n'
            reply = [wire.encode()]
            def serve():
                try:
                    while not stop.is_set():
                        try: conn,_=listener.accept()
                        except socket.timeout: continue
                        with conn:
                            connections.append(1); conn.settimeout(2)
                            try:
                                conn.sendall(reply[0])
                                incoming=conn.recv(4096)
                                assert not incoming, incoming  # No FTP/SMTP command, even HELO.
                            except (BrokenPipeError,ConnectionResetError):
                                pass  # The initial TCP reachability probe closes immediately.
                except Exception as error: failures.append(repr(error))
            worker=threading.Thread(target=serve); worker.start()
            base=['scan',host,'--ports',str(port),'--no-icmp','--no-multicast','--no-dns','--no-descriptions','--banners','--timeout','500ms']
            try:
                saved=Path(directory)/'snapshot.json'
                events=[json.loads(line) for line in run(*base,'--jsonl','--save',str(saved)).splitlines()]
                report=events[-1]['report']; device=report['devices'][0]; observation=device['ports'][0]
                match=observation['fingerprint']
                assert match['input']==value and match['field']==service+'.banner',match
                assert match['fields'].get('hw.product' if service=='ftp' else 'service.product')==product,match
                assert match['preference']==('0.90' if service=='ftp' else '0.20'),match
                assert json.loads(saved.read_text())==report
                assert [e['device'] for e in events if e['type']=='device_update']==[device]
                assert not device.get('mac') and not device.get('names') and not device.get('identity') and device.get('kind') in (None,'device') and not device['vendor'].get('name'),device
                if service=='ftp': assert match['fields']['host.mac']=='000400CEA560'
                else: assert match['fields']['host.name']=='foo.bar'
                assert len(connections)==2,connections
                row=list(csv.DictReader(io.StringIO(run(*base,'--csv'))))[0]
                assert row['service_fingerprints'].startswith(f'{port}/{service}: ') and not row['mac'] and not row['manufacturer'] and not row['model'],row
                plain=run(*base,'--details','--no-color')
                assert 'Catalog · TCP' in plain and match['reference'] in plain and ('host.mac = 000400CEA560' if service=='ftp' else 'host.name = foo.bar') in plain
                before=len(connections)
                disabled=json.loads(run(*base,'--banners=false','--json'))['devices'][0]['ports'][0]
                assert not disabled.get('banner') and not disabled.get('fingerprint') and len(connections)==before+1
                reply[0]=('220-'+text+'\r\n').encode()  # Missing terminator: timeout preserves diagnostic only.
                partial=json.loads(run(*base,'--json'))['devices'][0]['ports'][0]
                assert not partial.get('fingerprint') and partial['banner']=='220-'+text,partial
                reply[0]=('421 '+text+'\r\n').encode()
                refused=json.loads(run(*base,'--json'))['devices'][0]['ports'][0]
                assert not refused.get('fingerprint'),refused
                reply[0]=('220 '+text+'\x1b\r\n').encode()
                tainted=json.loads(run(*base,'--json'))['devices'][0]['ports'][0]
                assert tainted['banner']=='220 '+text and not tainted.get('fingerprint'),tainted
            finally:
                stop.set();worker.join(5)
                assert not worker.is_alive() and not failures,failures
        print(f'PASS {host} {service}: real CLI multiline recognition, no protocol commands, identity isolation, JSONL/snapshot, CSV/details, disable/refusal/partial/tainted boundaries')
