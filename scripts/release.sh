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
  cp LICENSE NOTICE THIRD_PARTY_LICENSES README.md "$stage/"
  python3 - "$stage" "dist/$archive.tar.gz" <<'PYARCHIVE'
import gzip,sys,tarfile
from pathlib import Path
stage=Path(sys.argv[1])
with open(sys.argv[2],'wb') as raw:
    with gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w') as tar:
            for name in ['lantern','LICENSE','NOTICE','THIRD_PARTY_LICENSES','README.md']:
                info=tar.gettarinfo(str(stage/name),arcname=name)
                info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=''
                info.mode=0o755 if name=='lantern' else 0o644
                with (stage/name).open('rb') as f:tar.addfile(info,f)
PYARCHIVE
  rm -rf "$stage"
  trap - EXIT HUP INT TERM
done
shasum -a 256 dist/lantern-"$version"-*.tar.gz > "dist/lantern-$version-checksums.txt"
