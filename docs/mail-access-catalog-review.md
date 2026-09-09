# IMAP and POP3 greeting catalogs

The integration adds all 18 IMAP and 30 POP3 patterns from the existing BSD-2-Clause [Recog revision d3d20938](https://github.com/rapid7/recog/tree/d3d20938da9f5f1e442c2419fe6c30cd651b6878). The [checked-in review manifest](../research/mail-access-catalog-review.json) records exact URLs, byte counts, SHA-256 hashes, and the compatibility experiment. The importer verifies those inputs and the existing pinned license files before replacing artifacts. No upstream executable code runs.

| Catalog | Field | Rules | Examples | Asserted captures |
| --- | --- | ---: | ---: | ---: |
| `xml/imap_banners.xml` | `imap4.banner` | 18 | 29 | 34 |
| `xml/pop_banners.xml` | `pop3.banner` | 30 | 39 | 44 |

The Go compatibility helper accepts all 68 examples and 78 asserted captures using the existing Ruby-anchor model; neither file has XML regex flags. Three IMAP and two POP examples match additional later rules, with no earlier-rule collisions. Source order therefore remains significant. Unlike the earlier FTP/SMTP review, no static/template assertions are left unevaluated by this experiment.

One IMAP example contains a horizontal tab in a Cyrus OS X greeting. The public matcher now permits tabs only for `imap4.banner`, preserving the input unchanged; every other control exception remains field-specific. IMAP/POP3 do not permit multiline fingerprint inputs. All 1,597 combined examples and 2,411 expected fields pass the public matcher, and all previous catalog records/examples remain unchanged.

The scanner strips only the positive greeting status prefix, preserving IMAP capability/response-code text. Refusals, partial lines, and later unsolicited lines do not become fingerprint inputs. Implicit TLS reuses these fields and keeps its transport service label. No mail commands or mailbox reads occur. Detailed protocol bounds and primary references are in [discovery](discovery.md#mail-access-greetings); catalog host/OS/software claims remain scoped port metadata.

Reproduce the hash-checked artifacts and all public examples with:

```sh
python3 scripts/build-banner-fingerprints.py --download
go test ./pkg/fingerprints -run TestAllCatalogExamplesAndProvenance
```

The read-only compatibility experiment can also be repeated against those downloaded files:

```sh
go run scripts/check-recog-patterns.go --ruby-flags research/downloads/recog/xml/imap_banners.xml research/downloads/recog/xml/pop_banners.xml
```

Examples and controlled loopback services do not establish physical mail-server coverage, accuracy for arbitrary/spoofed greetings, authentication, or complete upstream-runtime equivalence.
