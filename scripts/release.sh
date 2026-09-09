#!/bin/sh
# Local, reproducible release archives. This script does not publish anything.
set -eu
version=${1:-dev}
case "$version" in *[!a-zA-Z0-9._-]*) echo 'Invalid version' >&2; exit 1;; esac
mkdir -p dist
for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
  target_os=${target%/*}
  target_arch=${target#*/}
  archive="lantern-${version}-${target_os}-${target_arch}"
  stage=$(mktemp -d "${TMPDIR:-/tmp}/lantern-release.XXXXXX")
  trap 'rm -rf "$stage"' EXIT HUP INT TERM
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$version" -o "$stage/lantern" ./cmd/lantern
  python3 - "$stage" "dist/$archive.tar.gz" <<'PYARCHIVE'
import gzip,sys,tarfile
from pathlib import Path
stage=Path(sys.argv[1])
with open(sys.argv[2],'wb') as raw:
    with gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w') as tar:
            paths = [Path(name) for name in ['LICENSE','NOTICE','THIRD_PARTY_LICENSES','README.md','research/fing-inventory.json','research/fing-static-analysis.json','research/mail-access-catalog-review.json']]
            paths += [Path(name) for name in ['research/results/dhcp-catalog-review.md','research/results/dhcp-observation-verification.json']]
            paths += [Path('examples/identification')/name for name in ['truth.json','bindings.json','scan.json','normalized-run.json','android.json','snmp.json','inventory.json']]
            paths += sorted(Path('docs').glob('*.md'))
            paths += sorted(Path('pkg').glob('*/data/*.json'))
            inputs = [(Path('lantern'),stage/'lantern')] + [(p,p) for p in paths]
            for name, source in inputs:
                if source.is_symlink() or not source.is_file():
                    raise SystemExit(f'Release input must be a regular file: {source}')
                info=tar.gettarinfo(str(source),arcname=name.as_posix())
                info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=''
                info.mode=0o755 if name.as_posix()=='lantern' else 0o644
                with source.open('rb') as f:tar.addfile(info,f)
PYARCHIVE
  rm -rf "$stage"
  trap - EXIT HUP INT TERM
done
(
  cd dist
  shasum -a 256 lantern-"$version"-*.tar.gz > "lantern-$version-checksums.txt"
)
