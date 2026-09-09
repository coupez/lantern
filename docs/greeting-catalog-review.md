# FTP and SMTP greeting catalog review

The existing collector reads FTP and SMTP greetings, but the runtime fingerprint package currently interprets only SSH and HTTP Server fields. This review identifies **290 additional candidate rules** in the same pinned BSD-2-Clause Recog content revision, [`d3d20938`](https://github.com/rapid7/recog/tree/d3d20938da9f5f1e442c2419fe6c30cd651b6878). It imports no runtime data and leaves rc.5 unchanged.

| Input | Rules | Examples | Positional field assertions | Other assertions not evaluated | Examples matching multiple rules |
| --- | ---: | ---: | ---: | ---: | ---: |
| [FTP greeting text](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/xml/ftp_banners.xml) | 151 | 315 | 520 | 3 | 30 |
| [SMTP greeting text](https://github.com/rapid7/recog/blob/d3d20938da9f5f1e442c2419fe6c30cd651b6878/xml/smtp_banners.xml) | 139 | 235 | 575 | 1 | 15 |

All 290 expressions compile in Go 1.26.8 after the flag modeling described below. All 550 examples match their intended expression and all 1,095 directly asserted captures agree. No example matches an earlier rule in its file. Forty-five match additional later rules, so integration should retain source order. The four other assertions cover one static value and three field templates; the compatibility helper deliberately does not construct full output fields. This is finite example compatibility, not full Recog equivalence or physical-device accuracy.

## Regex flags

The earlier compatibility helper compiled the expression text directly and ignored XML `flags`. This caused eighteen FTP example mismatches. The FTP file has 22 rules with `REG_ICASE`, two with both `REG_ICASE` and `REG_MULTILINE`, and two with `REG_MULTILINE` alone. The SMTP file has no XML flag attributes, though some expressions specify inline flags.

The review pins the [Recog-Ruby flag factory](https://github.com/rapid7/recog-ruby/blob/0edce459788ea4e9364958e42cef1d2cb855aad8/lib/recog/fingerprint/regexp_factory.rb) separately from the content revision. That factory maps case flags to Ruby's ignore-case option and newline/multiline aliases to its multiline option. [Ruby's documented semantics](https://docs.ruby-lang.org/en/3.4/Regexp.html#class-Regexp-label-Multiline+Mode) make dot match newlines in that mode, while `^` and `$` are line anchors independently of the option. The helper's opt-in `--ruby-flags` mode models these with Go `(?m)`, plus `i` and `s` as applicable. It rejects unknown flags rather than silently treating them as defaults. No upstream implementation code is imported or executed.

This resolves the eighteen supplied-example failures. It does not establish equivalence for every Ruby/Go Unicode class, anchor, inline option, or regex feature. The original plain-Go mode remains available, and the previous pinned SSH/HTTP/Nmap review reproduces unchanged.

## Integration requirements

The FTP catalog expects greeting text after the numeric response prefix. Five source examples contain CRLF-separated text; two recognize a later line. Lantern currently returns the first FTP/SMTP diagnostic line, and its fingerprint API rejects all control characters. Runtime integration therefore needs deliberate, bounded handling of complete multiline greetings and field-specific line-ending validation. Removing control bytes or guessing arbitrary text to manufacture matches would lose the original observation semantics.

Greeting collection can remain read-only within the existing connection, byte, line, and timeout limits. FTP authentication/transfer commands, SMTP mail commands, and the separate SMTP EHLO/HELP/other-command catalogs are outside this reviewed input scope. Refusal, truncated, or malformed greetings should remain diagnostic observations without a fabricated recognized field.

Catalog outputs include `host.name`, `host.ip`, `host.mac`, and hardware serial claims. Those must remain attributed catalog interpretations rather than being promoted to observed addresses, neighbor MACs, or authenticated physical identity. The SMTP catalog's preference is `0.20`, while FTP uses `0.90`; these source qualifiers are not calibrated probabilities and must be preserved independently.

## Reproduction

`research/greeting-catalog-review.json` records exact input URLs, byte counts, SHA-256 hashes, source revisions, flag inventories, baseline failures, final counts, and limits. With the public inputs under `research/downloads/recog`, run:

```sh
python3 scripts/review-greeting-catalogs.py
python3 scripts/review-greeting-catalogs.py --self-test
```

Use `--download` to fetch the pinned public inputs with hash verification. The reviewer checks all input hashes before the Go experiment; self-tests cover line anchors, case/dot-newline flag aliases, unsupported flags, and changed input rejection. These commands never modify the embedded runtime catalog or send network probes. Raw downloads and execution logs remain ignored research artifacts.
