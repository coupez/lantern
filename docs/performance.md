# Performance measurements

Scan time depends on the requested probes, interface, device responses, kernel queues, and timeouts. The measurements below state their workload; they are not comparisons with Fing or guarantees for another network.

## Full-port result collection

The core's probe plan already deduplicates requested ports and excludes initial-discovery ports from the second phase. Every address/port pair therefore executes once. Previously, each open-port result still searched the entire list already recorded for that device. An all-open 65,535-port scan performed roughly two billion redundant comparisons while holding the result lock.

Collection now appends each observation directly and retains the existing final sort. This removes the quadratic search without introducing a per-device lookup table or allocating storage for unopened ports.

On an Apple M4 Max, Go 1.26.8, macOS ARM64, the synthetic `BenchmarkPortAggregation` produced these medians across five single-iteration samples:

| Concurrent workers | Before | After | Ratio |
| --- | ---: | ---: | ---: |
| 1 | 1,853.422 ms | 17.903 ms | 103.5× |
| 512 | 1,689.763 ms | 58.240 ms | 29.0× |

The injected dialer immediately reports every TCP port open on one address. ICMP, multicast, DNS, descriptions, and banners are disabled; there is no socket latency. The benchmark still exercises core scheduling, aggregation, service labels, coverage, and sorting. These numbers measure this worst-case bookkeeping workload, not overall LAN scan speed or the best concurrency setting for a real network. Sparse open-port results benefit less.

Reproduce the current benchmark with:

```sh
go test ./pkg/scanner -run '^$' -bench 'BenchmarkPortAggregation/ports-65535' -benchtime=1x -count=5 -benchmem
```

The reference engine was commit `13f34df`, measured in an isolated temporary source copy with the same benchmark. Neither compared run used CPU profiling. Raw results are recorded locally in `research/results/port-aggregation-baseline-fair.txt` and `research/results/port-aggregation-optimized-fair.txt`; medians are in `research/results/port-aggregation-summary.json`. These ignored development logs are not distributed datasets.

The regression test requests all ports on two addresses with duplicated input entries and discovery-phase overlaps. It checks every address/port is probed once, both sorted 65,535-port reports are complete, and mutations to initial/final event snapshots do not alter the returned report. A cancellation test checks unique partial results and that pending jobs stop.

## Full-range socket verification

`python3 scripts/test-full-ports.py` runs the actual CLI against a controlled IPv4 loopback listener, preferring port 65,535. It scans `1-65535` with 64 workers and a 100 ms TCP timeout, disables other discovery/enrichment, and verifies complete requested coverage, the listener's open-port observation, and unique sorted results without errors. Existing local listeners are allowed as additional observations.

The macOS ARM64 run completed in 1,094 ms. This verifies an actual full-range scan; it is not the all-open synthetic workload above and is not a measurement against remote devices. The fixture also runs in CI and both Linux architecture suites. See [platform testing](platform-testing.md) and [verification results](verification.md).
