# DHCP/DHCPv6 catalog review

Reviewed 2026-09-09. Bounded source files are retained locally in the ignored directory `research/downloads/dhcp-catalog-review`; they are not redistributed in release archives. Immutable upstream links and hashes appear below. Counts come from parsing XML/section records, not line counts.

## Candidate A: xnih/satori fingerprints

Pinned upstream revision: [`xnih/satori` commit `73fa88fe6549995c68760be10631382df4ec1d1c`](https://github.com/xnih/satori/tree/73fa88fe6549995c68760be10631382df4ec1d1c), dated 2025-12-24. The downloaded files were fetched again from immutable commit URLs and hashes matched:

| file | source | bytes | SHA-256 | records | test rows |
| --- | --- | ---: | --- | ---: | ---: |
| DHCPv4 XML | [`fingerprints/dhcp.xml`](https://raw.githubusercontent.com/xnih/satori/73fa88fe6549995c68760be10631382df4ec1d1c/fingerprints/dhcp.xml) | 458,578 | `4f64a405fb1debbd2e066478a7190b821424e0691399068421fdaf168da09b14` | 481 `<fingerprint>` records | 2,787 `<test>` rows; 1,605 unique full test signatures |
| DHCPv6 XML | [`fingerprints/dhcpv6.xml`](https://raw.githubusercontent.com/xnih/satori/73fa88fe6549995c68760be10631382df4ec1d1c/fingerprints/dhcpv6.xml) | 6,261 | `213858a4d5f763582855b20a1caa257cfefdba51a4ac39410dd33a65f05f008e` | 9 records | 27 test rows; 12 unique full test signatures |

The repository’s [`LICENSE`](https://raw.githubusercontent.com/xnih/satori/73fa88fe6549995c68760be10631382df4ec1d1c/LICENSE) is GPL-2.0 for the project. The current XML files have no separate data license or permission notice; they contain per-record authors and old vendor URLs, but that is not a redistribution grant. An older 2014 mirror included a request to notify the author and link Satori, but that notice is not present in the pinned current files. The safe conclusion is GPL-2.0 project licensing plus unclear/separately authored fingerprint-data provenance, requiring upstream clarification before embedding rows in a permissively licensed Lantern release.

Matching is richer than option 55 alone. A test may require exact or partial matching of DHCP message type (`Discover`, `Request`, `Inform`, or `Any`), complete DHCP option sequence (`dhcpoptions`), parameter-request-list sequence (`dhcpoption55`), vendor class string (`dhcpvendorcode`), and observed IP TTL; each test has a weight. The XML records labels such as device type/vendor and sometimes OS/version. Satori’s source code and the XML schema therefore provide a useful import shape for a collector, but Lantern must preserve the observed fields and the winning test evidence rather than collapse a vector into an asserted identity.

Ambiguity is material. Among full test signatures, 342 of 1,605 unique DHCPv4 signatures map to more than one named record; the largest maps to 56 labels. DHCPv6 has 5 ambiguous signatures among 12 unique signatures, with a maximum of 6 labels. In particular, an option-55-only match can be shared by unrelated devices; the catalog needs message type, vendor class, option sequence and/or TTL when available. Do not infer a model or OS from option 55 alone. DHCPv6 coverage is tiny and old despite the file’s 2024-05-27 metadata date.

## Candidate B: Fingerbank public/current paths and legacy snapshot

The current public API is the only maintained access path I could verify. [Fingerbank API documentation](https://api.fingerbank.org/api_doc/2/combinations/interrogate.html) requires an API key, accepts both `dhcp_fingerprint` and `dhcp6_fingerprint`, and documents that the option list must preserve the order seen in the packet. It combines multiple attributes and returns a device result; the [usage examples](https://www.fingerbank.org/usage/) show a score of 75 for an Android-family DHCP fingerprint alone and 81 when vendor/user-agent context identifies a Galaxy S6. The API may add unknown combinations to the upstream database, so queries are not a sealed offline catalog. The current database download endpoint returns `Missing key` without credentials; no current public bulk file was available for pinning.

For a bounded offline comparison, I downloaded the historical [`karottc/fingerbank` `dhcp_fingerprints.conf`](https://raw.githubusercontent.com/karottc/fingerbank/e2aa41d0514435d454287dd31bf4d34fa750c73a/dhcp_fingerprints.conf) at immutable commit `e2aa41d0514435d454287dd31bf4d34fa750c73a`, dated 2014-11-14. It is 39,077 bytes, SHA-256 `89a4aba486c104c073227db9967031e6de54dc90057511bf6a3ddac1c7581035`, with 238 `[os]` records, 25 class records, 539 fingerprint-vector rows, and 538 unique vectors. One vector maps to two OS labels (`Debian-based Linux` and `Linux Ubuntu 14.04`). The file header explicitly states [ODbL 1.0](https://opendatacommons.org/licenses/odbl/1.0/) for the database and [DBCL 1.0](https://opendatacommons.org/licenses/dbcl/1.0/) for individual contents. This is clearer data licensing than Satori, but the snapshot is stale and has no DHCPv6 records.

The current Fingerbank service is operationally feasible as an optional adapter: observe DHCPv4/v6 packets, submit only the documented ordered fingerprint plus any available vendor/user-agent context, retain the returned score/device hierarchy/source timestamp, and require a user API key. It is unsuitable as a core offline catalog unless the user supplies a licensed on-prem/bulk database. Do not treat its score as a probability or authenticated identity.

## Decision

Use **Fingerbank API or an explicitly user-supplied licensed database** as the near-term integration target. It is maintained, supports DHCPv4 and DHCPv6, documents ordered matching semantics, and exposes ambiguity through a score and hierarchy. Lantern should make network submission opt-in, redact or avoid unrelated attributes by default, and record the exact observed DHCP fields and API response metadata.

Do **not** embed Satori’s XML in Lantern at this stage. It has useful coverage and a concrete DHCPv6 grammar, but current data licensing is unclear beyond the GPL-2 project license, its DHCPv6 catalog is only 9 records, and signature collisions are substantial. Satori remains a useful user-supplied/import-format reference if its data authors grant redistribution rights.

Neither catalog justifies a retail model or OS claim from option 55 alone. The collector should emit the raw ordered options, message type, vendor/user class where present, DHCPv6 option request/rapid-commit details where present, and a catalog candidate with source, score/weights, and competing labels.
