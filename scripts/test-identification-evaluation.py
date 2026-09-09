#!/usr/bin/env python3
"""Compiled-CLI checks using deliberately synthetic, independently scored labels."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'bin/lantern'
EXAMPLES = ROOT / 'examples/identification'

class EvaluationCLI(unittest.TestCase):
    def run_cli(self, *args, ok=True):
        p = subprocess.run([str(BIN), 'evaluate', *map(str, args)], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode == 0, ok, p.stdout + p.stderr)
        return p

    def test_scan_scores(self):
        args = ['--truth', EXAMPLES/'truth.json', '--scan', EXAMPLES/'scan.json', '--bindings', EXAMPLES/'bindings.json']
        output = json.loads(self.run_cli(*args, '--json').stdout)
        result = output['evaluation']
        g = result['overall']
        self.assertEqual((g['cases'], g['observed'], g['responsive'], g['fragmentation']), (5, 4, 3, 1))
        self.assertEqual(result['unmapped'], ['192.0.2.99'])
        s = g['fields']['reported_model']
        self.assertEqual([s[k] for k in ['correct','incorrect','ambiguous','unknown','missed','unlabeled']], [1,1,0,1,1,1])
        self.assertEqual((s['precision'], s['recall']), (0.5, 0.25))
        s = g['fields']['retail_model']
        self.assertEqual([s[k] for k in ['correct','incorrect','ambiguous','unknown','missed','unlabeled']], [0,1,1,1,0,2])
        self.assertEqual(result['dataset_kind'], 'synthetic')
        self.assertEqual(result['by_state']['asleep']['cases'], 2)
        self.assertEqual({i['role']:i['sha256'] for i in output['inputs']}, {role:hashlib.sha256((EXAMPLES/name).read_bytes()).hexdigest() for role,name in [('truth','truth.json'),('scan','scan.json'),('bindings','bindings.json')]})
        human = self.run_cli(*args).stdout
        self.assertIn('synthetic dataset', human)
        self.assertIn('Observed 4/5', human)
        self.assertIn('25.0%', human)

    def test_neutral_run(self):
        output = json.loads(self.run_cli('--truth', EXAMPLES/'truth.json', '--run', EXAMPLES/'normalized-run.json', '--json').stdout)['evaluation']
        self.assertEqual(output['system'], 'example-scanner')
        self.assertEqual(output['overall']['observed'], 1)
        self.assertEqual(output['overall']['fields']['retail_model']['recall'], 1/3)

    def test_mapping_typo_even_when_address_missed(self):
        bindings = json.loads((EXAMPLES/'bindings.json').read_text())
        bindings['addresses']['192.0.2.3'] = 'typo-missing-case'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'bindings.json'
            path.write_text(json.dumps(bindings))
            p = self.run_cli('--truth', EXAMPLES/'truth.json', '--scan', EXAMPLES/'scan.json', '--bindings', path, ok=False)
            self.assertIn('unknown case', p.stderr)
            self.assertEqual(p.stdout, '')

    def test_bad_input_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'truth.json'
            for raw in ['{"schema":1,"schema":1}', (EXAMPLES/'truth.json').read_text() + '{}']:
                p.write_text(raw)
                self.run_cli('--truth', p, '--run', EXAMPLES/'normalized-run.json', ok=False)
        self.run_cli('--truth', EXAMPLES/'truth.json', '--run', EXAMPLES/'normalized-run.json', '--scan', EXAMPLES/'scan.json', ok=False)

if __name__ == '__main__':
    unittest.main()
