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

## Watch redraws with large results

The dashboard previously rebuilt complete search strings on every redraw, including when no search was active. It also formatted every service in each visible row before truncation and regenerated the entire selected inspector at 10 Hz.

Watch now creates search text only when needed, reuses filtered/sorted device lists and the selected inspector, and builds service summaries only to the visible column width. Completed reports and live first-scan device updates invalidate these views. Progress-only updates preserve them; changing the query, selected device, or terminal width refreshes the relevant view. Search still includes every port and the inspector retains every detail row.

On the same Apple M4 Max / Go 1.26.8 / macOS ARM64 environment, medians of three samples with three iterations each measured the following steady redraws at 120 columns × 40 rows:

| Synthetic report | View | Before | After | Allocation before → after |
| --- | --- | ---: | ---: | ---: |
| 1,024 devices × 14 open ports | List | 2.561 ms | 0.727 ms | 1.61 MB → 71.6 KB |
| 16 devices × 65,535 open ports | List | 294.937 ms | 0.143 ms | 302.63 MB → 26.8 KB |
| 16 devices × 65,535 open ports | Search | 373.240 ms | 0.141 ms | 302.63 MB → 26.9 KB |
| 16 devices × 65,535 open ports | Inspector | 232.933 ms | 0.024 ms | 184.51 MB → 16.9 KB |

Both revisions receive the same synthetic reports, service labels, query, dimensions, and one untimed initial frame. The reference is commit `129ba3c` with the same benchmark file. The search query is `65535/unknown`, which matches every device in the full-port report. These are in-memory rendering measurements without network traffic, terminal writes, or CPU profiling; they are not scan-speed or end-to-end input-latency claims.

View construction still costs work. For the 16-device/full-port report, invalidating all device views before each frame measured 0.177 ms for the list, 95.004 ms for first search, and 168.834 ms for first inspector layout. Search text is retained for the current report, and wrapped inspector lines for one selected device; that memory is released when the report changes. Extremely large first-time searches/inspections can still pause drawing briefly. The optimization avoids paying that cost on every idle tick or progress update.

```sh
go test ./internal/ui -run '^$' -bench BenchmarkWatchLargeResults -benchtime=3x -count=3 -benchmem
go test ./internal/ui -run '^$' -bench BenchmarkWatchBuildViews -benchtime=3x -count=3 -benchmem
```

Regression tests compare width-limited service summaries with full rendering across Unicode/control cases; verify searching and scrolling to port 65,535; and exercise report/device updates, progress-only reuse, selection, resize, and firmware search refreshes. Local measurements are in `research/results/watch-large-baseline.txt`, `watch-large-optimized.txt`, `watch-build-views.txt`, and `watch-render-summary.json` (ignored development evidence).

## Search across identity claims

`BenchmarkWatchClaimSearch` uses 1,024 synthetic devices, 14 ports and 64 identity claims per device, and a 120×40 watch frame. On the Apple M4 Max (macOS ARM64), medians of three samples with five iterations each were **14.312 ms** to build/filter search text after a report change, **0.976 ms** to change a query using the cached text, and **0.302 ms** for a steady filtered redraw. Median allocations were 10,742,107, 229,688, and 71,993 bytes respectively. These are local UI workloads, not discovery latency or real-network throughput.

Identity claim fields and values are appended with a string builder, avoiding repeated copying of the growing index for each claim. The index remains lazy and cached; reports without an active query do not build it. Logs and calculated medians: `research/results/watch-claims-benchmark.log` and `.json` (ignored).
