# Banner catalog source review

Recog is the next candidate for extending Lantern's offline recognition. Its pinned SSH and HTTP catalogs supply 608 patterns over data Lantern already collects. This review checks source provenance and matching feasibility; these patterns are not yet embedded in the scanner.

## Recog

Reviewed revision: [`d3d20938da9f5f1e442c2419fe6c30cd651b6878`](https://github.com/rapid7/recog/tree/d3d20938da9f5f1e442c2419fe6c30cd651b6878), retrieved 2026-09-09. The repository's [LICENSE](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/LICENSE) assigns BSD-2-Clause to its files; [COPYING](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/COPYING) supplies the redistribution conditions and disclaimer. Both were downloaded and hashed. A future import must retain the notice in source and packaged releases.

| Input | Patterns | Examples checked | Capture assertions checked | Examples matching multiple patterns |
| --- | ---: | ---: | ---: | ---: |
| [SSH software/comment text](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/xml/ssh_banners.xml) | 152 | 227 | 368 | 95 |
| [HTTP Server header](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/xml/http_servers.xml) | 456 | 752 | 846 | 28 |

All 608 expressions compile unchanged with Go 1.26.8's `regexp`. Every example matches its own expression, and all 1,214 directly asserted capture values agree. Twenty other HTTP example assertions, covering values outside these plain positional captures, are deliberately not evaluated. No example matches an earlier expression in its file, although 123 match additional later expressions. That supports preserving the catalog's specificity/order rather than merging all matching patterns as independent evidence.

This is a finite compatibility experiment, not proof of complete Recog equivalence or real-device accuracy. The experiment does not implement parameter defaults, compound versions, value templates, CPE processing, certainty interpretation, or full upstream output construction. It does not execute upstream Ruby or Python. Unicode/regex edge semantics beyond supplied examples remain untested.

A runtime integration should retain separate service, operating-system, and hardware catalog claims with exact source provenance and qualifiers. An OpenSSH service vendor must not become the physical device manufacturer. HTTP fingerprinting must receive an actual Server field, not the banner reader's fallback HTTP status line. SSH patterns expect the portion after `SSH-<protocol-version>-`, including optional comments, not the entire identification line. Raw observations must stay available, and banner interpretation must not issue additional probes or authenticate a hardware identity.

The SSH input review exposed an existing collector gap: RFC-compliant preamble lines hid the later identification string. The collector now prefers a literal `SSH-` line within its existing byte, line, and deadline bounds; see [discovery behavior](discovery.md#tcp-probes-and-service-banners). This fix does not itself import or apply Recog fingerprints.

## Nmap

Reviewed revision: [`08312c289b74551e49d5fd51e54d9d3f18f53ac9`](https://github.com/nmap/nmap/tree/08312c289b74551e49d5fd51e54d9d3f18f53ac9), retrieved 2026-09-09. The pinned [LICENSE](https://github.com/nmap/nmap/blob/08312c289b74551e49d5fd51e54d9d3f18f53ac9/LICENSE) is NPSL version 0.95; the [service-probe file](https://github.com/nmap/nmap/blob/08312c289b74551e49d5fd51e54d9d3f18f53ac9/nmap-service-probes) explicitly refers to those terms. This project has not selected those terms for its MIT core and has not imported either catalog. This is an integration decision, not a claim that all open-source reuse is forbidden.

The service database contains 104 TCP and 84 UDP probe definitions, 11,970 `match` lines and 203 `softmatch` lines. Those are syntax counts, not unique models or independently verified recognitions. Adopting them would require their probe/response semantics and applicable licensing to be addressed; this review does not execute probes or evaluate their regex behavior.

The [MAC table](https://github.com/nmap/nmap/blob/08312c289b74551e49d5fd51e54d9d3f18f53ac9/nmap-mac-prefixes) contains 52,085 prefixes: 38,930 /24, 6,262 /28, and 6,893 /36. Exact-width comparison with Lantern's 58,421 IEEE records finds 52,081 shared prefixes, four Nmap-only prefixes, and 6,340 Lantern-only prefixes. Two extras have the local-address bit; the other two, `00FFD1` and `B0C420`, are labeled as virtual NICs for Cooperative Linux and Bochs. These do not establish new physical-manufacturer mappings. Any future virtual-NIC interpretation should be independently checked against the respective implementation and represented separately from the IEEE registrant. Name spelling and real-device accuracy were not compared.

## Reproduction

`research/banner-catalog-review.json` records pinned URLs, byte counts, SHA-256 hashes, the Lantern index hash, aggregate results, decisions, and limits. Place its inputs under `research/downloads/recog` and `research/downloads/nmap`, retaining relative paths, then run at the repository root:

```sh
python3 scripts/review-banner-catalogs.py
```

The Python reviewer checks every input hash before invoking the Go compatibility experiment. Go reports the hashes it actually read as an additional consistency check. Only aggregate results are emitted. The recorded comparison reproduced exactly; modifying a temporary SSH input was rejected before pattern evaluation. Downloaded catalogs and result logs remain ignored research artifacts and are not bundled in releases.
