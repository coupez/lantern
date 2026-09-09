# Wireshark manufacturer-source review

The pinned Wireshark manufacturer table adds **zero globally administered unicast prefixes** absent from Lantern's current IEEE index. Its extra entries should not be used to assign a manufacturer to randomized/private MAC addresses.

The review used Wireshark revision `857d9b98e9d70c0f0666bea18c3b2b060e5bd93b`, retrieved on 2026-09-09. The [generated manufacturer table](https://github.com/wireshark/wireshark/blob/857d9b98e9d70c0f0666bea18c3b2b060e5bd93b/epan/manuf-data.c) and [generator](https://github.com/wireshark/wireshark/blob/857d9b98e9d70c0f0666bea18c3b2b060e5bd93b/tools/make-manuf.py) identify IEEE as the registry source, including CID alongside MA-L, MA-M, MA-S and IAB. The generator's Python and the generated C were inspected as text; neither was executed.

| Prefix comparison | Entries |
| --- | ---: |
| Lantern IEEE index | 58,421 |
| Wireshark manufacturer tables | 58,195 |
| Shared exact prefixes | 57,976 |
| Wireshark-only prefixes | 219 |
| Wireshark-only globally administered unicast prefixes | 0 |
| Wireshark-only locally administered prefixes | 219 |
| Lantern-only prefixes | 445 |

Comparison preserves the 24-, 28-, and 36-bit prefix widths. Wireshark contains 39,871 /24, 6,579 /28, and 11,745 /36 entries. Of Lantern's 445 unmatched entries, 436 are named `IEEE Registration Authority`; Wireshark's generator explicitly omits these subdivision-holder records. Entry-count differences therefore do not establish better device recognition. This review compares prefix coverage, not equivalent vendor-name spelling or real-device accuracy.

IEEE explains that [CID identifiers cannot generate universally unique MAC addresses](https://standards.ieee.org/products-programs/regauth/cid/). The Wireshark-only entries all have the local-address bit set, and its generator includes CID. A separate direct download of the CID CSV returned HTTP 418, so exact CID membership of every extra prefix was not independently verified. A local MAC matching one of these prefixes is not enough to establish manufacturer identity; Lantern retains its private/randomized label.

Wireshark's separate [well-known-address file](https://github.com/wireshark/wireshark/blob/857d9b98e9d70c0f0666bea18c3b2b060e5bd93b/wka) contains 246 entries. Of these, 194 have the multicast bit and 73 have the local-address bit; these categories overlap. The file includes protocol, virtual-router, and other reserved-address labels, rather than a retail hardware-model catalog. Some address roles may be useful future recognition hints, but should be checked against their primary protocol specifications and kept distinct from MAC registrants.

The inspected generator, generated table, and well-known-address file carry `GPL-2.0-or-later` SPDX headers; the upstream COPYING file was also retained and hashed. No Wireshark table or code was imported into Lantern's runtime or release archives. The existing direct IEEE sources remain the manufacturer-data source.

Source URLs, hashes, the pinned Lantern index hash, aggregate results, and the decision are recorded in `research/wireshark-manufacturer-review.json`. Downloaded files and detailed intermediate comparisons remain in ignored research directories. To reproduce, place the four pinned upstream files at their listed relative paths under `research/downloads/wireshark`, then run:

```sh
python3 scripts/compare-wireshark-manuf.py
```

The comparison verifies every input hash before parsing and emits aggregate counts only. The prepared rc.4 archives remain unchanged.
