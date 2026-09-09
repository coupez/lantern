# Performance measurements

Scan time depends on the requested probes, interface, device responses, kernel queues, and timeouts. The measurements below state their workload; they are not comparisons with Fing or guarantees for another network.

## Virtual MAC range lookup

On macOS ARM64 / Apple M4 Max with Go 1.26.8, three warm samples measured a median **99.68 ns/op** for `00:00:5e:00:01:2a` (120 bytes, four allocations) and **76.04 ns/op** for the ordinary-address `BenchmarkLookup` (24 bytes, two allocations). Virtual range results include independently owned metadata and references. These measurements exclude lazy database initialization and network activity. Reproduce with `go test ./pkg/vendors -run '^$' -bench 'Benchmark(VirtualMACLookup|Lookup)$' -benchmem -count=3`. Local log: `research/results/virtual-mac-lookup-benchmark.log` (ignored).

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

## Offline Matter product lookup

On macOS ARM64 / Apple M4 Max, `BenchmarkMatterProductLookup` measured **117.8 ns/op** median across three samples (112.8–123.2 ns/op), with 308 bytes and five allocations per returned result. It resolves an exact vendor/product pair against the 998-pair SmartThings catalog and returns an independently owned match with provenance. This warm measurement excludes the first lazy decompression/JSON load and all network activity; it is not a scan-time benchmark. Reproduce with `go test ./pkg/models -run '^$' -bench BenchmarkMatterProductLookup -benchmem -count=3`. Log: `research/results/matter-product-benchmark.log` (ignored).

## Comparing repeated port observations

Snapshot and watch comparisons previously copied, sorted, and formatted both devices' port lists before checking whether the sets differed. Comparing 16 unchanged devices with all 65,535 ports created over two million temporary allocations.

The core now checks equal ordered port numbers directly. When lists differ, it filters to shared requested coverage, sorts and deduplicates owned numeric lists, and compares those before formatting changed sets. Legacy snapshots and custom core reports can still supply unordered or duplicate port observations. Changed sets retain their complete numeric ordering and independently owned structured values.

`BenchmarkDiffPortObservations` uses 16 devices with separately owned before/after lists. The changed case removes the highest port from one device; the other fifteen stay unchanged. On Apple M4 Max / Go 1.26.8 / macOS ARM64, medians of three samples with three iterations each were:

| Ports observed per device | Change | Before | After | Allocated bytes before → after |
| --- | --- | ---: | ---: | ---: |
| 14 | None | 0.0205 ms | 0.0131 ms | 11,880 → 3,688 |
| 14 | One device loses one port | 0.0266 ms | 0.0123 ms | 13,608 → 5,928 |
| 65,535 | None | 27.357 ms | 0.920 ms | 52,669,048 → 3,688 |
| 65,535 | One device loses one port | 31.317 ms | 6.685 ms | 60,254,520 → 10,618,605 |

These are in-memory core comparisons without network traffic, terminal output, or CPU profiling. Reports are built outside the timed section, and both revisions use the same benchmark. Changed large sets still cost memory to format and return; this does not truncate their contents. The reference is `d144ced`. Raw logs and calculated medians are under `research/results/diff-ports-{baseline.log,optimized.log,summary.json}` (ignored).

```sh
go test ./pkg/scanner -run '^$' -bench BenchmarkDiffPortObservations -benchtime=3x -count=3 -benchmem
```


## Offline banner fingerprint matching

On Apple M4 Max / macOS ARM64 / Go 1.26.8, medians of three warm `BenchmarkLookup` samples measured:

| Input | Median | Bytes / allocations per operation |
| --- | ---: | ---: |
| SSH `OpenSSH_9.9p1 Ubuntu-3ubuntu1` | 3.662 µs | 2,054 / 40 |
| HTTP Server `Apache/2.4.65` | 1.381 µs | 831 / 18 |
| Unmatched HTTP Server, 2,048 `x` bytes | 135.711 µs | 0 / 0 |

The matcher preserves source order and returns independently owned scoped fields with expanded catalog templates. Input length is bounded to 2,048 bytes. These warm measurements exclude initial lazy decompression/JSON parsing/compilation and all network/terminal work; they do not measure overall scan time or accuracy. Unmatched long inputs require more regex work than early matching rules. Reproduce with `go test ./pkg/fingerprints -run '^$' -bench BenchmarkLookup -benchmem -count=3`. Log: `research/results/banner-fingerprints-benchmark.log` (ignored).


## Required-text prechecks for banner matching

A CPU profile of the maximum-length unknown HTTP Server workload showed regex execution dominating matching time. A few unanchored or leading-wildcard patterns account for much of that work. Each rule now has a conservative literal-text precheck derived from Go's parsed regex tree during initial catalog setup. Missing required text skips that regex; candidate rules still execute the original expression in source order. Printable ASCII input validation also takes a short path, and the rule loop avoids copying complete rule records.

On the same Apple M4 Max / macOS ARM64 / Go 1.26.8 environment, medians of three 500 ms samples compared `6e02654` with the optimized implementation using the same benchmark fixture:

| Warm lookup input | Before | After | Ratio |
| --- | ---: | ---: | ---: |
| Unknown HTTP `LanternUnknown/2026` | 9.094 µs | 2.135 µs | 4.26× |
| Unknown HTTP, 2,048 `x` bytes | 136.281 µs | 10.593 µs | 12.87× |
| Nonmatch, 2,000 `x` bytes followed by `-EmWeb/` | 130.733 µs | 60.013 µs | 2.18× |
| HTTP `Apache/2.4.65` | 1.388 µs | 1.202 µs | 1.15× |
| SSH `OpenSSH_9.9p1 Ubuntu-3ubuntu1` | 3.640 µs | 3.023 µs | 1.20× |
| Late HTTP match `Example KNX-IP Interface` | 11.399 µs | 3.463 µs | 3.29× |

The third workload contains a required literal but still does not match its rule, so the precheck cannot eliminate its regex execution. Presence of a literal never establishes a catalog match. These are in-memory lookup measurements with unchanged inputs, outputs, and catalog data; they are not overall network-scan speedups or accuracy measurements. Neither comparison run used CPU profiling.

There is an initialization tradeoff: repeated full catalog initialization rose from **5.117 ms to 5.823 ms**, with total allocated bytes per initialization increasing from **8,424,526 to 9,597,417**. This measures decompression, JSON parsing, compilation, and precheck derivation, excluding process startup. Initialization occurs once when the catalog is first used; ASTs are not retained after derivation. Warm successful-match allocation counts remain 18 for Apache, 40 for the SSH example, and 13 for the late HTTP match. The three negative workloads report zero allocations per operation at benchmark precision.

```sh
go test ./pkg/fingerprints -run '^$' -bench 'Benchmark(RequiredTextWorkloads|Initialization)$' -benchmem -benchtime=500ms -count=3
```

Raw measurements and calculated medians: `research/results/fingerprint-required-{baseline.log,final-benchmark.log,summary.json}` (ignored). The separate CPU profile and per-rule timing experiment are diagnostic evidence only and are not used for the ratios above.
