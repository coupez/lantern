#!/usr/bin/env python3
"""Importer boundary checks; independent of downloaded research inputs."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('banner_import', ROOT/'scripts/build-banner-fingerprints.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def xml(body):
    return ('<fingerprints matches="ssh.banner" protocol="ssh" preference="0.90">'+body+'</fingerprints>').encode()

class ImportTests(unittest.TestCase):
    def test_literal_fields_order_and_comments(self):
        data = xml('''<!-- <fingerprint pattern="comment"/> -->
<fingerprint pattern="^Example_(.*)$" certainty="0.50">
<description>Example software</description><example service.version="1.2">Example_1.2</example>
<param name="service.product" pos="0" value="Example"/><param name="service.version" pos="1"/>
</fingerprint>''')
        catalog, examples = module.extract(data)
        self.assertEqual(catalog['rules'][0]['line'], 2)
        self.assertEqual(catalog['rules'][0]['certainty'], '0.50')
        self.assertEqual(catalog['rules'][0]['params'][1], {'name':'service.version','pos':1})
        self.assertEqual(examples, [{'rule':0,'input':'Example_1.2','fields':{'service.version':'1.2'}}])

    def test_greeting_flag_mapping(self):
        for flags, prefix in [('REG_ICASE','(?mi)'), ('REG_MULTILINE','(?ms)'), ('REG_ICASE,REG_MULTILINE','(?mis)'), ('','(?m)')]:
            data = xml(f'<fingerprint pattern="^Example$" flags="{flags}"><description>x</description></fingerprint>').replace(b'ssh.banner',b'ftp.banner').replace(b'protocol="ssh"',b'protocol="ftp"')
            catalog, _ = module.extract(data)
            self.assertEqual(catalog['rules'][0]['pattern'],prefix+'^Example$')
        with self.assertRaises(ValueError):
            module.extract(xml('<fingerprint pattern="x" flags="unknown"><description>x</description></fingerprint>').replace(b'ssh.banner',b'ftp.banner'))

    def test_mail_fields_preserve_text(self):
        for field in ['imap4.banner', 'pop3.banner']:
            data = xml('<fingerprint pattern="^Example(.*)$"><description>x</description><example>Example&#x9;value</example></fingerprint>').replace(b'ssh.banner',field.encode())
            catalog, examples = module.extract(data)
            self.assertEqual(catalog['field'],field)
            self.assertEqual(catalog['rules'][0]['pattern'],'(?m)^Example(.*)$')
            self.assertEqual(examples[0]['input'],'Example\tvalue')

    def test_unsupported_or_ambiguous_input(self):
        for body in [
            '<fingerprint pattern="x" flags="i"><description>x</description></fingerprint>',
            '<fingerprint pattern="x"><description>x</description><param name="a" pos="0" value="a"/><param name="a" pos="0" value="b"/></fingerprint>',
            '<fingerprint pattern="x"><description>x</description><param name="a" pos="1" value="a"/></fingerprint>',
            '<fingerprint pattern="x"><description>x</description><param name="a" pos="-1"/></fingerprint>',
            '<fingerprint pattern="x"><description>x</description><example _filename="/etc/passwd"/></fingerprint>',
            '<fingerprint pattern="x"><description>x</description><script>execute()</script></fingerprint>',
        ]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                module.extract(xml(body))
        with self.assertRaises(ValueError):
            module.extract(b'<!DOCTYPE x [<!ENTITY x "expanded">]>'+xml(''))
        with self.assertRaises(ValueError):
            module.extract(xml('').decode().encode('utf-16'))

    def test_hash_failure_preserves_artifacts(self):
        paths = [ROOT/'pkg/fingerprints/data/recog.json.gz', ROOT/'pkg/fingerprints/data/sources.json', ROOT/'pkg/fingerprints/testdata/examples.json.gz']
        before = [hashlib.sha256(p.read_bytes()).digest() for p in paths]
        with tempfile.TemporaryDirectory(prefix='lantern-banner-import-') as directory:
            Path(directory,'LICENSE').write_text('changed source')
            result = subprocess.run([sys.executable,str(ROOT/'scripts/build-banner-fingerprints.py'),'--source-dir',directory],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('SHA-256 mismatch',result.stderr)
        self.assertEqual(before,[hashlib.sha256(p.read_bytes()).digest() for p in paths])

if __name__ == '__main__':
    unittest.main()
