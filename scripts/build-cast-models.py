#!/usr/bin/env python3
"""Import only literal model data from a pinned, MIT-licensed source; never execute it."""
import ast
import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'research/downloads/pychromecast'
commit = json.loads((source / 'commit.json').read_text())['sha']
content = (source / 'const.py').read_bytes()
names = {}
models = {}
for node in ast.parse(content).body:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        continue
    key = node.targets[0].id
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        names[key] = node.value.value
    elif key == 'CAST_TYPES':
        if not isinstance(node.value, ast.Dict):
            raise ValueError('Unexpected model table syntax')
        for model, values in zip(node.value.keys, node.value.values):
            if not isinstance(model, ast.Constant) or not isinstance(model.value, str) or not isinstance(values, ast.Tuple) or len(values.elts) != 2 or not all(isinstance(v, ast.Name) for v in values.elts):
                raise ValueError('Non-literal model entry')
            models[model.value] = {'cast_type': names[values.elts[0].id], 'manufacturer': names[values.elts[1].id]}
if len(models) < 30:
    raise ValueError('Unexpectedly small model registry')
output = {
    'source': {
        'url': f'https://github.com/home-assistant-libs/pychromecast/blob/{commit}/pychromecast/const.py',
        'commit': commit,
        'sha256': hashlib.sha256(content).hexdigest(),
        'retrieved': datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        'license': 'MIT',
    },
    'models': dict(sorted(models.items())),
}
(root / 'pkg/scanner/data/cast-models.json').write_text(json.dumps(output, indent=2)+'\n')
print(f'Imported {len(models)} Cast models')
