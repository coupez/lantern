#!/usr/bin/env python3
"""Compare fresh-process offline fingerprint latency with identical CLI output."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('before', type=Path)
parser.add_argument('after', type=Path)
parser.add_argument('--samples', type=int, default=30)
args = parser.parse_args()
if args.samples < 3:
    parser.error('at least three samples are required')
executables = {key: path.resolve() for key, path in [('before', args.before), ('after', args.after)]}
cases = {
    'count': [],
    'http': ['http', 'Apache/2.4.65'],
    'ssh': ['ssh', 'OpenSSH_9.9p1 Ubuntu-3ubuntu1'],
    'ftp': ['ftp', 'SYNOLOGY FTP server ready.'],
    'smtp': ['smtp', 'foo.bar ESMTP Postfix (3.1.4)'],
    'unknown-http': ['http', 'LanternUnknown/2026'],
}
report = {
    'platform': platform.platform(),
    'scope': 'Fresh process per sample; warm filesystem/code pages; includes process launch, CLI startup, lookup, and captured output; no sockets.',
    'samples_per_binary_per_case': args.samples,
    'binaries': {key: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for key, path in executables.items()},
    'cases': {},
}
for name, parameters in cases.items():
    samples = {key: [] for key in executables}
    expected = None
    for iteration in range(args.samples + 3):
        # Alternate order and exclude three warm-up pairs from timing summaries.
        order = list(executables)
        if iteration % 2:
            order.reverse()
        for key in order:
            start = time.perf_counter_ns()
            result = subprocess.run([str(executables[key]), 'fingerprint', *parameters], capture_output=True, check=True)
            elapsed = time.perf_counter_ns() - start
            if result.stderr:
                raise RuntimeError(f'{name}/{key}: unexpected stderr {result.stderr!r}')
            if expected is None:
                expected = result.stdout
            if result.stdout != expected:
                raise RuntimeError(f'{name}/{key}: output differs')
            if iteration >= 3:
                samples[key].append(elapsed)
    medians = {key: statistics.median(values) for key, values in samples.items()}
    report['cases'][name] = {
        'arguments': ['fingerprint', *parameters],
        'output_sha256': hashlib.sha256(expected).hexdigest(),
        'samples_ns': samples,
        'median_ns': medians,
        'before_over_after': medians['before'] / medians['after'],
    }
print(json.dumps(report, indent=2))
