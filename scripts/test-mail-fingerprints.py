#!/usr/bin/env python3
"""Actual IMAP/POP3 and implicit-TLS CLI fixtures on owned ports 110/143/993/995.

Requires low-port bind permission; runs inside the isolated Linux test container.
"""
import ast
import csv
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

binary = str(Path(sys.argv[1] if len(sys.argv)>1 else 'bin/lantern').resolve())
# Reuse only literal public fixture credentials; do not execute the HTTP test script.
source = ast.parse(Path(__file__).with_name('test-banner-fingerprints.py').read_text())
constants = {node.targets[0].id: ast.literal_eval(node.value) for node in source.body
             if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id in ('TLS_CERT', 'TLS_KEY')}
def run(*args):
    result = subprocess.run([binary,*args],capture_output=True,text=True,check=True,timeout=15)
    if '--details' not in args: assert not result.stderr, result.stderr
    return result.stdout

for service,port,secure in [('imap',143,False),('pop3',110,False),('imaps',993,True),('pop3s',995,True)]:
    is_imap = service.startswith('imap')
    field = 'imap4.banner' if is_imap else 'pop3.banner'
    prefix = '* OK ' if is_imap else '+OK '
    text = '[CAPABILITY IMAP4rev1] example.com Cyrus IMAP4 v2.3.7 server ready' if is_imap else 'Dovecot ready. <fea.13865d.5f06b0a4.DuIvzQI4DAGR9MurahIGJw==@foo.bar.baz>'
    hostname = 'example.com' if is_imap else 'foo.bar.baz'
    product = 'Cyrus IMAP' if is_imap else 'Dovecot'
    offline = json.loads(run('fingerprint','imap' if is_imap else 'pop3',text))
    assert offline['field']==field and offline['fields']['service.product']==product
    for family,host in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
        with tempfile.TemporaryDirectory(prefix='lantern-mail-') as directory, socket.socket(family) as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6: listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            listener.bind((host,port)); listener.listen(8); listener.settimeout(.1)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert,key=Path(directory)/'cert.pem',Path(directory)/'key.pem'
            cert.write_text(constants['TLS_CERT']); key.write_text(constants['TLS_KEY'])
            context.load_cert_chain(cert,key)
            context.set_alpn_protocols(['h2','http/1.1'])
            names=[]
            context.set_servername_callback(lambda sock,name,ctx: names.append(name))
            stop=threading.Event(); failures=[]; connections=[]
            reply=[(prefix+text+'\r\n').encode()]
            def serve():
                try:
                    while not stop.is_set():
                        try: conn,_=listener.accept()
                        except socket.timeout: continue
                        connections.append(1)
                        try:
                            conn.settimeout(2)
                            if secure:
                                conn=context.wrap_socket(conn,server_side=True)
                                assert conn.selected_alpn_protocol() is None
                            conn.sendall(reply[0])
                            incoming=conn.recv(4096)
                            assert not incoming, incoming
                        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError,ssl.SSLZeroReturnError):
                            pass  # TCP reachability probe closes without a TLS handshake.
                        finally: conn.close()
                except Exception as error: failures.append(repr(error))
            worker=threading.Thread(target=serve);worker.start()
            base=['scan',host,'--ports',str(port),'--no-icmp','--no-multicast','--no-dns','--no-descriptions','--banners','--timeout','500ms']
            try:
                saved=Path(directory)/'snapshot.json'
                events=[json.loads(line) for line in run(*base,'--jsonl','--save',str(saved)).splitlines()]
                report=events[-1]['report']; device=report['devices'][0]; observation=device['ports'][0]
                assert observation['service']==service
                match=observation['fingerprint']
                assert match==offline and match['fields']['host.name']==hostname,match
                assert json.loads(saved.read_text())==report
                assert [e['device'] for e in events if e['type']=='device_update']==[device]
                assert not device.get('mac') and not device.get('names') and not device.get('identity') and device.get('kind') in (None,'device'),device
                assert len(connections)==2,connections
                row=list(csv.DictReader(io.StringIO(run(*base,'--csv'))))[0]
                assert row['service_fingerprints'].startswith(f'{port}/{service}: ') and not row['mac'] and not row['manufacturer'],row
                details=run(*base,'--details','--no-color')
                assert match['reference'] in details and f'host.name = {hostname}' in details
                before=len(connections)
                disabled=json.loads(run(*base,'--banners=false','--json'))['devices'][0]['ports'][0]
                assert not disabled.get('banner') and not disabled.get('fingerprint') and len(connections)==before+1
                for wire in [prefix+text, ('* BYE ' if is_imap else '-ERR ')+text+'\r\n', prefix+text+'\x1b\r\n']:
                    reply[0]=wire.encode()
                    rejected=json.loads(run(*base,'--json'))['devices'][0]['ports'][0]
                    assert not rejected.get('fingerprint'),rejected
                if is_imap:
                    reply[0]=('* PREAUTH '+text+'\r\n').encode()
                    assert json.loads(run(*base,'--json'))['devices'][0]['ports'][0]['fingerprint']==offline
                assert all(name is None for name in names),names
            finally:
                stop.set();worker.join(5)
                assert not worker.is_alive() and not failures,failures
        print(f'PASS {host} {service}: real CLI recognition, no mail commands/SNI/HTTP ALPN, identity isolation, events/snapshot, CSV/details, disabled and malformed replies')
