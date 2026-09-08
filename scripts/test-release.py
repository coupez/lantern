#!/usr/bin/env python3
"""Inspect release archives; optionally run both Linux and Intel Mac binaries."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('version', nargs='?', default='dev')
parser.add_argument('--linux-containers', action='store_true', help='also execute both Linux archives in the architecture-specific local test images')
parser.add_argument('--macos-amd64', action='store_true', help='on macOS also execute the Intel archive; Apple Silicon requires installed Rosetta')
args = parser.parse_args()
version = args.version
if not re.fullmatch(r'[A-Za-z0-9._-]+',version):
    raise SystemExit('Invalid release version')
dist = root/'dist'
targets = [('darwin','arm64'),('darwin','amd64'),('linux','arm64'),('linux','amd64')]
expected = {f'lantern-{version}-{system}-{arch}.tar.gz' for system,arch in targets}
checksums = {}
for line in (dist/f'lantern-{version}-checksums.txt').read_text().splitlines():
    digest,name = line.split(maxsplit=1)
    assert name == Path(name).name, 'checksums must work from the download directory'
    assert name not in checksums
    checksums[name] = digest
assert set(checksums) == expected, checksums
host = (platform.system().lower(), {'aarch64':'arm64','x86_64':'amd64'}.get(platform.machine().lower(),platform.machine().lower()))
if args.macos_amd64 and host[0] != 'darwin':
    raise SystemExit('--macos-amd64 requires macOS')
required = {'lantern','LICENSE','NOTICE','THIRD_PARTY_LICENSES','README.md','docs/install.md',
            'docs/snapshots.md','docs/discovery.md','docs/recognition.md','docs/verification.md',
            'docs/STATUS.md','docs/fing-research.md','research/fing-inventory.json',
            'pkg/models/data/sources.json','pkg/vendors/data/sources.json','pkg/scanner/data/sources.json',
            'pkg/scanner/data/cast-models.json'}
for system,arch in targets:
    filename = f'lantern-{version}-{system}-{arch}.tar.gz'
    path = dist/filename
    assert hashlib.sha256(path.read_bytes()).hexdigest() == checksums[filename]
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        names = {m.name for m in members}
        assert len(names)==len(members) and required <= names, names
        content = {}
        for entry in members:
            name = PurePosixPath(entry.name)
            assert not name.is_absolute() and '..' not in name.parts and name.as_posix()==entry.name
            assert entry.isfile(), entry.name
            assert entry.mtime==0 and entry.uid==0 and entry.gid==0 and not entry.uname and not entry.gname
            assert entry.mode == (0o755 if entry.name=='lantern' else 0o644)
            assert entry.name in required or re.fullmatch(r'docs/[^/]+\.md|pkg/[^/]+/data/[^/]+\.json',entry.name)
            content[entry.name] = archive.extractfile(entry).read()
        assert b'github.com/rivo/uniseg' in content['THIRD_PARTY_LICENSES']
        assert b'AppleDB' in content['NOTICE']
        for name,data in content.items():
            if name.endswith('.json'):
                json.loads(data)
            if name.endswith('.md'):
                for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',data.decode()):
                    url = urlsplit(target)
                    if url.scheme or url.netloc or not url.path:
                        continue
                    link = posixpath.normpath(posixpath.join(posixpath.dirname(name),unquote(url.path)))
                    assert link in names, (name,target,'missing offline link')
        binary = content['lantern']
        if system=='darwin':
            assert binary[:4]==bytes.fromhex('cffaedfe')
            assert struct.unpack_from('<I',binary,4)[0] == {'arm64':0x100000c,'amd64':0x1000007}[arch]
        else:
            assert binary[:6]==b'\x7fELF\x02\x01'
            assert struct.unpack_from('<H',binary,18)[0] == {'arm64':183,'amd64':62}[arch]
        if (system,arch)==host or (args.macos_amd64 and system == 'darwin' and arch == 'amd64'):
            with tempfile.TemporaryDirectory(prefix='lantern-release-') as directory:
                exe = Path(directory)/'lantern'
                exe.write_bytes(binary)
                exe.chmod(0o755)
                def run(*args):
                    return subprocess.run([str(exe),*args],check=True,capture_output=True,text=True,timeout=10).stdout
                assert run('version').strip()==f'lantern {version}'
                assert '4 devices' in run('demo','--no-color')
                assert 'cisco' in json.loads(run('lookup','00:00:0c:12:34:56'))['name'].lower()
                assert json.loads(run('models','Mac16,9'))
                diagnostics = json.loads(run('doctor', '--json'))
                assert diagnostics['os'] == system and diagnostics['arch'] == arch, diagnostics
                assert diagnostics['version'] == version, diagnostics
                if args.macos_amd64 and system == 'darwin':
                    for fixture in ['test-event-stream.py', 'test-watch-pty.py', 'test-snapshot-cli.py']:
                        subprocess.run(['python3', str(root/'scripts'/fixture), str(exe)], check=True, timeout=90)
                print(f'PASS packaged runtime: {system}/{arch}',flush=True)
    if system == 'linux' and args.linux_containers:
        image = f'lantern-linux-test:{arch}'
        inspected = subprocess.run(['docker', 'image', 'inspect', image, '--format', '{{.Os}}/{{.Architecture}}'], check=True, capture_output=True, text=True, timeout=15)
        assert inspected.stdout.strip() == f'linux/{arch}', inspected.stdout
        # Transfer only the verified binary through stdin; no host mounts,
        # capabilities, or external networking are needed for these fixtures.
        verify = r"""
import json, os
from pathlib import Path
import subprocess, sys, tempfile
with tempfile.TemporaryDirectory(prefix='lantern-archive-') as tmp:
    exe = Path(tmp) / 'lantern'
    exe.write_bytes(sys.stdin.buffer.read())
    exe.chmod(0o755)
    def run(*args):
        return subprocess.run([str(exe), *args], check=True, capture_output=True, text=True, timeout=15).stdout
    assert run('version').strip() == 'lantern ' + os.environ['LANTERN_EXPECT_VERSION']
    assert '4 devices' in run('demo', '--no-color')
    assert 'cisco' in json.loads(run('lookup', '00:00:0c:12:34:56'))['name'].lower()
    assert json.loads(run('models', 'Mac16,9'))
    report = json.loads(run('doctor', '--json'))
    assert report['os'] == 'linux' and report['arch'] == os.environ['LANTERN_EXPECT_GOARCH'], report
    assert report['version'] == os.environ['LANTERN_EXPECT_VERSION'], report
    for fixture in ['test-event-stream.py', 'test-watch-pty.py', 'test-snapshot-cli.py']:
        subprocess.run(['python3', '/usr/local/bin/' + fixture, str(exe)], check=True, timeout=90)
"""
        result = subprocess.run(['docker', 'run', '--rm', '-i', '--platform', f'linux/{arch}',
                                 '--network', 'none', '--cap-drop', 'ALL',
                                 '-e', f'LANTERN_EXPECT_VERSION={version}', '-e', f'LANTERN_EXPECT_GOARCH={arch}',
                                 image, 'python3', '-c', verify], input=binary, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.flush()
        result.check_returncode()
        print(f'PASS packaged Linux runtime and CLI fixtures: linux/{arch}', flush=True)
    print(f'PASS archive, checksum, architecture, licensing, provenance, and offline links: {filename}',flush=True)
