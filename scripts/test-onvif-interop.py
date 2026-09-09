#!/usr/bin/env python3
"""Optional, pinned simulator-handler interoperability; no sockets or media needed."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = '0285e2ae69180c5e347d13372458713664a51f8b'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True, help='checkout of GyeongHoKim/onvif-simulator at the pinned revision')
parser.add_argument('--go', default='go', help='Go 1.26.8+ executable')
args = parser.parse_args()
source = args.source.resolve()
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
if revision != REVISION:
    raise SystemExit(f'Expected simulator revision {REVISION}; got {revision}')
if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=source, text=True).strip():
    raise SystemExit('Simulator tracked files must match the pinned revision')
with tempfile.TemporaryDirectory(prefix='lantern-onvif-interop-') as directory:
    task = Path(directory)
    shutil.copyfile(ROOT/'scripts/testdata/onvif-interop/main.go', task/'main.go')
    # Match the simulator module namespace so Go permits its internal service
    # handler import. No upstream code is edited or embedded into Lantern.
    (task/'go.mod').write_text('module github.com/GyeongHoKim/onvif-simulator/lanterninterop\n\ngo 1.26.8\n\nrequire (\n github.com/GyeongHoKim/onvif-simulator v0.0.0\n github.com/coupez/lantern v0.0.0\n)\n' +
        'replace github.com/GyeongHoKim/onvif-simulator => '+json.dumps(str(source))+'\n' +
        'replace github.com/coupez/lantern => '+json.dumps(str(ROOT))+'\n')
    env = dict(os.environ, GOTOOLCHAIN='local')
    subprocess.run([args.go, 'build', '-mod=mod', '-o', str(task/'check'), '.'], cwd=task, env=env, check=True, timeout=180)
    subprocess.run([str(task/'check')], cwd=task, env=env, check=True, timeout=10)
