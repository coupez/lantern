#!/usr/bin/env python3
"""Verify canonical go install/core imports through a local file-only proxy.

Dependencies must already be in the Go module download cache (go mod download).
All installation, consumer-module, and staging writes stay in a temporary tree.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
module = 'github.com/coupez/lantern'
version = 'v0.0.0-installtest'

def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=180, **kwargs).stdout

def escaped(path):
    return ''.join('!'+c.lower() if c.isupper() else c for c in path)

try:
    goroot = Path(run(['go','env','GOROOT'], cwd=root).strip())
    cache = Path(run(['go','env','GOMODCACHE'], cwd=root).strip())
    listing = run(['go','list','-deps','-json','./cmd/lantern'], cwd=root, env={**os.environ,'GOPROXY':'off'})
    decoder, modules = json.JSONDecoder(), {}
    while listing.strip():
        entry, end = decoder.raw_decode(listing.lstrip())
        listing = listing.lstrip()[end:]
        dependency = entry.get('Module')
        if dependency and not dependency.get('Main'):
            modules[dependency['Path']] = dependency

    with tempfile.TemporaryDirectory(prefix='lantern-install-') as directory:
        temp = Path(directory)
        proxy = temp/'proxy'
        for dependency in modules.values():
            path, rev = escaped(dependency['Path']), dependency['Version']
            source = cache/'cache/download'/path/'@v'
            target = proxy/path/'@v'
            target.mkdir(parents=True)
            for suffix in ['mod','info','zip']:
                item = source/(rev+'.'+suffix)
                if not item.is_file():
                    raise RuntimeError(f'Missing {item}; run go mod download before the offline test')
                shutil.copyfile(item, target/item.name)
            (target/'list').write_text(rev+'\n')

        destination = proxy/module/'@v'
        destination.mkdir(parents=True)
        (destination/(version+'.mod')).write_bytes((root/'go.mod').read_bytes())
        (destination/(version+'.info')).write_text(json.dumps({'Version':version,'Time':'2026-09-08T00:00:00Z'}))
        (destination/'list').write_text(version+'\n')
        sources = [root/name for name in ['go.mod','go.sum','LICENSE','NOTICE','THIRD_PARTY_LICENSES','README.md']]
        for name in ['cmd','internal','pkg']:
            sources.extend(p for p in (root/name).rglob('*') if p.is_file())
        with zipfile.ZipFile(destination/(version+'.zip'),'w',zipfile.ZIP_DEFLATED) as archive:
            for source in sorted(sources):
                if source.is_symlink():
                    raise RuntimeError(f'Module input must be a regular file: {source}')
                archive.write(source, f'{module}@{version}/{source.relative_to(root).as_posix()}')

        work = temp/'outside-checkout'
        work.mkdir()
        env = {**os.environ, 'PATH':str(goroot/'bin')+os.pathsep+os.environ['PATH'],
               'GOPROXY':proxy.as_uri(), 'GOSUMDB':'off', 'GONOPROXY':'', 'GOPRIVATE':'',
               'GONOSUMDB':'', 'GOWORK':'off', 'GOFLAGS':'', 'GOTOOLCHAIN':'local',
               'GOMODCACHE':str(temp/'modules'), 'GOPATH':str(temp/'gopath'),
               'GOCACHE':str(temp/'build-cache'), 'GOBIN':str(temp/'bin')}
        go = str(goroot/'bin/go')
        run([go,'install',f'{module}/cmd/lantern@{version}'], cwd=work, env=env)
        binary = temp/'bin/lantern'
        assert run([str(binary),'version'],env=env).strip() == f'lantern {version}'
        assert '4 devices' in run([str(binary),'demo','--no-color'],env=env)
        print('PASS canonical versioned go install outside the checkout; installed version and offline demo', flush=True)

        (work/'go.mod').write_text(f'module example.test/consumer\n\ngo 1.26.8\n\nrequire {module} {version}\n')
        (work/'main.go').write_text('''package main
import (
 "context"
 "fmt"
 "net/netip"
 "github.com/coupez/lantern/pkg/scanner"
 "github.com/coupez/lantern/pkg/vendors"
 "github.com/coupez/lantern/pkg/models"
 "github.com/coupez/lantern/pkg/fingerprints"
)
func main() {
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 options:=scanner.Defaults();options.Target=netip.MustParsePrefix("192.0.2.1/32")
 options.Ports=nil;options.ICMP=false;options.Multicast=false;options.Resolve=false
 engine:=scanner.Engine{NeighborSource:func(context.Context)(map[netip.Addr]string,error){return nil,nil}}
 report,err:=engine.Scan(ctx,options,nil)
 if err!=nil || !report.Cancelled || report.Probed!=0 { panic("cancellation contract") }
 if vendors.Count()<58000 || len(models.Lookup("Mac16,9"))==0 { panic("embedded data missing") }
 match:=fingerprints.Lookup(fingerprints.HTTPServer,"Apache/2.4.65")
 if fingerprints.Count()!=898 || match==nil || match.Fields["service.product"]!="HTTPD" { panic("banner catalog missing") }
 ftp:=fingerprints.Lookup(fingerprints.FTPBanner,"ET000400CEA560 Lexmark T640 FTP Server NS.NP.N219 ready.")
 smtp:=fingerprints.Lookup(fingerprints.SMTPBanner,"foo.bar ESMTP Postfix (3.1.4)")
 if ftp==nil || ftp.Fields["host.mac"]!="000400CEA560" || smtp==nil || smtp.Fields["service.product"]!="Postfix" { panic("greeting catalog missing") }
 copy:=match.Clone();copy.Fields["service.product"]="changed"
 if match.Fields["service.product"]!="HTTPD" { panic("banner match ownership") }
 fmt.Println("core import OK")
}
''')
        assert run([go,'run','-mod=mod','.'],cwd=work,env=env).strip() == 'core import OK'
        print('PASS independent consumer imports core packages and embedded datasets', flush=True)

        staging = temp/'staging area'
        run(['make','install','PREFIX=/opt/lantern test',f'DESTDIR={staging}'],cwd=root,env=env)
        staged = staging/'opt/lantern test/bin/lantern'
        assert staged.is_file() and os.access(staged,os.X_OK)
        assert '4 devices' in run([str(staged),'demo','--no-color'],env=env)
        print('PASS make install with PREFIX/DESTDIR containing spaces; no system installation', flush=True)
        marker = temp/'unexpected-command'
        invalid = subprocess.run(['make','release',f'VERSION=bad;touch {marker}'],cwd=root,env=env,capture_output=True,text=True,timeout=10)
        assert invalid.returncode != 0 and not marker.exists()
        assert 'Invalid version' in invalid.stderr, (invalid.stdout,invalid.stderr)
        print('PASS invalid release version rejected without interpreting it as shell commands', flush=True)
except subprocess.CalledProcessError as error:
    print(error.stdout or '', end='')
    print(error.stderr or '', end='')
    raise
