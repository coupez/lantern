# Device recognition

Lantern combines independent MAC assignment records with device-reported protocol data. Its core keeps those different kinds of evidence separate; a randomized MAC can still accompany a useful model advertisement.

## Data paths

| Input | Extracted information | Basis |
| --- | --- | --- |
| NetBIOS node status (UDP 137) | Active unique computer names, workgroups, raw registration bytes/flags, reported unit ID | Unauthenticated registration claims; no OS, manufacturer, or open-port inference |
| IEEE MA-L / MA-M / MA-S / IAB | Registered MAC organization | Registry assignment; not the retail brand |
| Bonjour printing `_ipp`, `_ipps`, `_printer`, `_pdl-datastream` | `usb_MFG`, `usb_MDL`, `ty`, `product` | Advertised manufacturer, model, or display description |
| `_airplay._tcp`, `_device-info._tcp`; `_raop._tcp` | `model`; `am` | Original advertised model identifier |
| Pinned AppleDB hardware catalog | 606 identifiers → 886 assignments, including 124 ambiguous identifiers | Catalog-derived product-name candidates; all source variants retained |
| `_esphomelib._tcp` (ESPHome) | Friendly name, firmware version, build board/platform, project metadata | Protocol-derived firmware label; advertised build details, without retail model/manufacturer inference |
| `_shelly._tcp` → `/shelly` | Instance name; reported model, name, firmware version/build, generation, application/profile | Device-reported JSON; no link-layer MAC inference |
| Pinned aioshelly catalog (Apache-2.0) | 155 exact identifiers → names/generations | Catalog candidates and Shelly brand label; automatic matches require the reported generation |
| `_hap._tcp` (HomeKit) | `md` model, instance name, `ci` category | Advertised name/model plus source-linked protocol category interpretation |
| `_googlecast._tcp` | `md`, `fn` | Advertised model and friendly name |
| Pinned PyChromecast catalog | 40 exact Cast model → manufacturer mappings | Catalog-derived, explicitly labeled |
| WS-Discovery ProbeMatches | ONVIF `name` / `hardware` scope URIs | Advertised name and hardware description; endpoint types and URLs retained as metadata |
| SSDP → UPnP description | `friendlyName`, `manufacturer`, `modelName`, `modelNumber`, `deviceType`, `UDN` | Device-reported XML; embedded devices stay distinct |

The `identity` object offers selected name/manufacturer/model/firmware fields, plus all recognized claims and their provenance. The advertised `model` remains unchanged. `model_names` contains unique, sorted catalog candidates for that selected model; one candidate is a catalog interpretation, and several candidates indicate unresolved variants. Each catalog claim records the exact input identifier and pinned source-file URL. Explicit standardized fields precede printer display descriptions; catalog-derived manufacturer claims rank below device-reported manufacturer fields. Ties are resolved deterministically by source/key/value, not packet arrival order. Catalog names and manufacturers attach only to the selected model claim; metadata from a conflicting, unselected model cannot silently populate the selected identity. Conflicting claims remain visible. A claim is not an authenticated hardware identity.

The CLI shows identity fields in `inspect` / `--details`; JSON and saved snapshots retain claims and raw advertisements. CSV includes reported-name, manufacturer, model, model-candidate, firmware, and firmware-version columns. The two firmware columns are appended after `model_candidates`; earlier column positions stay the same.

## Shelly recognition

Standard/deep mDNS discovery directly queries `_shelly._tcp`, including when service enumeration is unanswered. The service supplies a generic smart-home type hint, an instance-name fallback, and a generation claim when its `gen` TXT value is a valid integer of at least 2. Other TXT fields do not become model or firmware claims.

With descriptions enabled, this exact service triggers one read-only `GET /shelly` on the discovered IP and advertised port. URL/path/host values in TXT cannot redirect the request. Generic HTTP services and hostname patterns do not trigger it. Shelly and UPnP together share at most four unique request targets and one per-device `--timeout`; duplicate Shelly advertisements reuse the endpoint result, including failures. `--no-descriptions` disables these reads. No authentication, control, update, or configuration endpoint is called.

The JSON response must contain a generation of at least 2 and nonempty `id`/`model` strings. Its reported name and model populate identity fields; `ver` supplies the firmware version with a protocol-derived Shelly firmware label. Build, generation, application, profile, and reported MAC become provenance claims. Firmware/version selection stays tied to the same endpoint and device ID. A separate catalog can add a product-name candidate and brand label when both the model identifier and generation agree. These data never overwrite observed MACs, establish authentication/security state, or add a verified-open port to the TCP scan results.

Reads use the same pinned-IP, no-proxy, no-redirect transport as UPnP. Headers are capped at 16 KiB; JSON at 16 KiB; selected strings at 2 KiB before display normalization. Duplicate top-level keys, invalid types, incomplete identities, trailing documents, and unsupported generation-1 replies are rejected. Unknown extension fields are ignored within the body cap. Failures leave the original mDNS record intact. Shelly Gen1 recognition and physical-device interoperability remain pending.

Semantics were checked on 2026-09-08 against Shelly's official [mDNS documentation](https://shelly-api-docs.shelly.cloud/gen2/General/mDNS/) and [device-information endpoint](https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Shelly/#http-endpoint-shelly). No upstream API implementation is incorporated.

### Shelly catalog

The independent [aioshelly device table](https://github.com/home-assistant-libs/aioshelly/blob/8f1b2f9bf2fc154faf6c3d73213d59620a6e301c/aioshelly/const.py), under Apache-2.0, contributes 155 exact model-name/generation records. `SNSW-001X16EU` with generation 2, for example, gains the catalog candidate `Shelly Plus 1`. The original model code remains selected; name and manufacturer claims are labeled `catalog`, tied to the same endpoint/model claim, and retain the pinned URL and exact input identifier. `Shelly` is a catalog brand label, separate from a MAC registrant or a device-reported manufacturer.

Missing/mismatched generations, unknown codes, generic HTTP TXT, and Apple protocol fields cannot trigger these matches. A competing model that wins selection cannot inherit another endpoint's Shelly catalog name or manufacturer. Apple protocol fields use the AppleDB namespace; the generic offline lookup covers both catalogs. Existing unknown devices keep their reported model and firmware without invented product names.

The importer reads only Python AST literal constants and device-table fields, without importing/executing upstream code. It pins source/license SHA-256 values, keeps every name/generation record including entries whose control support is marked unavailable upstream, and omits implementation, firmware requirements, control capabilities, and Bluetooth IDs. Catalog inclusion does not prove discoverability or control support. Gen1 records are available offline, while automatic Shelly discovery still requires the implemented Gen2+ path.

Rebuild with `python3 scripts/build-shelly-models.py --download --retrieved 2026-09-08`; omit `--download` for the pinned local inputs. The fixed retrieval date reproduces the index and metadata. `pkg/models/data/shelly-sources.json` records hashes, revision, license, counts, and selection rules; the Apache license is retained in `THIRD_PARTY_LICENSES` and adaptations are described in `NOTICE`.

`lantern models SNSW-001X16EU` returns the offline match with generation and provenance. There are 761 identifiers across AppleDB and Shelly. `lantern models sources` now returns an array with both catalog sources. Core callers can use `models.Sources()`; the original `models.Provenance()` still returns AppleDB metadata. `models.LookupShelly(code, generation)` supports scoped lookups; generation zero means all catalog generations for explicit offline use.

## ESPHome recognition

Standard/deep discovery now queries `_esphomelib._tcp` directly, so ESPHome devices can be found even when service-type enumeration is unanswered. PTR, SRV, TXT, and address records can arrive separately. The existing shared deadline and query/packet budgets still apply; this adds one initial service question and no device API connection. Quick mode still requires `--no-multicast=false` to enable mDNS.

The exact service identifies the advertised firmware as ESPHome (`basis: "protocol"`). The `friendly_name` TXT value supplies a display name; a valid service instance supplies a lower-priority fallback. `version` populates `identity.firmware_version`, while `identity.firmware` remains separate from the hardware model. Both fields appear in JSON, saved snapshots, CSV, plain output, and the inspector; watch search includes them. A version is selected only from the same advertised instance as the chosen firmware claim. Other instances' versions remain visible as competing claims, including when the selected instance omitted its version.

`board`, `platform`, `project_name`, and `project_version` become source-linked build/project claims. They describe firmware configuration and do not establish a retail device model or manufacturer. The advertised `mac` stays in TXT metadata; it cannot replace link-layer observations. Advertised ports remain unverified until a TCP probe confirms them. Import URLs are retained but never fetched, and advertised encryption metadata is not treated as a verified security assessment.

Recognition requires the exact service and mDNS protocol, with normal DNS case-insensitivity. Generic HTTP advertisements with similar TXT keys are insufficient. The generic smart-home type hint yields to more specific HomeKit, printer, router, hub, and media service evidence. Firmware versions are compared as observed strings with the same multicast-coverage and partial-scan safeguards as other identity fields. There is no claim that a particular board, firmware project, or version authenticates a physical device.

Protocol semantics were checked against [ESPHome's pinned mDNS implementation](https://github.com/esphome/esphome/blob/1ce0bed3f672d3a4699dad0cbfd8617c3b8950e5/esphome/components/mdns/mdns_component.cpp), SHA-256 `2b04cfea602306e369ff45660d3e25d369f082de47d11800a58e160bfa8deae0`. No upstream implementation code is incorporated. IPv4/IPv6 socket fixtures verify this path; physical ESPHome-device coverage remains pending.

## HomeKit recognition

HomeKit advertisements already participate in standard/deep mDNS discovery. Their `md` field now supplies a model claim and their DNS-SD instance supplies a name, including embedded dots and original spelling. No pairing, authentication, accessory control, or additional network request is involved.

The `ci` field maps 36 known category codes to type hints such as light, outlet, thermostat, camera, speaker, television, and smart home hub. Category claims use `field: "kind"`, `basis: "protocol"`, the original numeric `identifier`, and a `reference` URL pinned to the checked protocol table. Model/name claims keep `basis: "advertised"`. JSON, snapshots, and the CLI details view preserve the evidence.

Unknown/malformed categories fall back to a generic smart home device. Multiple different specific categories on one IP also stay generic; all claims remain available rather than choosing whichever packet arrived first. Existing printer, UPnP router, and Home Assistant hub advertisements retain precedence. Recognition requires the correct protocol and exact service type, so lookalike names do not become recognized services. A HomeKit model is not matched against Cast or Apple hardware catalogs, and category codes never supply a manufacturer. The HomeKit `id` remains an advertised protocol identifier and does not replace the observed MAC.

## Model catalog import

AppleDB explicitly licenses its device data under MIT. Revision `95f799d28e45dc110ee2f25b7e3e6cf8c1124dae` contributes public hardware identifiers in `family,number` form, including Mac, iPhone, iPad, Apple TV, HomePod, AirPort, Apple Watch, and accessory identifiers. Internal/prototype records, software, SDKs, simulators, and virtual machines are excluded. These are lookup records; inclusion does not imply that a device advertises its identifier or is discoverable over Wi-Fi.

The importer verifies all 1,905 JSON device input files against the pinned Git blob inventory and retains source SHA-256 values per assignment. It reads selected JSON directly from the archive, without extracting paths or executing upstream code. The index is 46,306 bytes compressed. `pkg/models/data/sources.json` records source revision, date, license hash, archive hash, index hash, counts, and selection rules. The upstream MIT license is retained in `THIRD_PARTY_LICENSES`.

Rebuild using `python3 scripts/build-apple-models.py --download --retrieved 2026-09-08`. Omit `--download` to reuse local source files. The revision is deliberately pinned; updating it requires updating the reviewed commit/tree/license constants. The same pinned inputs and retrieval date reproduce the index and metadata byte-for-byte.

`lantern models IDENTIFIER` returns every matching source record as JSON, including names, types, manufacturer labels, source URLs, and hashes. Lookup ignores surrounding whitespace and case, but never uses prefixes or fuzzy matches. Apple hardware records are labeled Apple; records typed as Beats products are labeled Beats. These are catalog brand labels, separate from IEEE MAC assignments.

## Discovery behavior and limits

mDNS asks for common services plus the DNS-SD service-type enumeration record. PTR records lead to missing SRV/TXT queries, and SRV targets lead to missing A or AAAA queries for the scan’s address family. Names and TXT records may arrive in separate packets. TXT keys must be nonempty printable ASCII; malformed keys are ignored. Valid keys are case-insensitive and the first occurrence of a duplicate key wins. Values remain unchanged in memory until interpretation, so removing controls cannot create a valid category or catalog match. JSON escapes controls, and terminal rendering sanitizes them. Human-readable instance spelling from a PTR target survives lowercase follow-up replies. Follow-ups stay in `.local.` and consume a fixed 128-query budget; the original socket deadline never extends. Advertised ports are not reported as verified open TCP ports.

mDNS, SSDP, and WS-Discovery each process at most 512 received datagrams, including ignored/malformed traffic. mDNS also caps query attempts at 128, including initial questions and follow-ups. Reaching either limit adds a completeness warning while retaining decoded observations. A query limit stops new questions but allows pending replies to arrive within the existing response window. Unexpected receive errors and query/short-write failures also retain already-decoded data and add a warning. Normal read-deadline expiry and cancellation do not become socket-failure warnings. SSDP multicast hop-limit setup errors are reported before querying.

UPnP description requests only accept HTTP URLs with a literal IP matching the SSDP responder. The transport pins that address and disables proxies and redirects. Four unique request targets, shared with Shelly identity reads, use one per-device timeout. Response headers, body size (256 KiB), XML depth (32), device count (64), and field lengths are bounded. Repeated recognized identity fields (including empty fields or equivalent namespace prefixes) and nested markup inside those fields reject the whole description, preventing concatenated or truncated identity values. Ordinary text, CDATA, comments, and separate embedded-device fields remain supported. The USN's device UUID is matched to the description's UDN before attaching a model, so an embedded device does not silently inherit the root device's identity. Unknown, malformed, inaccessible, or unmatched descriptions leave the original SSDP advertisement intact.

Quick mode skips multicast and descriptions by default. NetBIOS is opt-in for quick/standard and enabled for deep IPv4/inspect; `--netbios=false` disables it. Explicit boolean flags override profile defaults, including `--no-multicast=false` and `--banners=false`.

## Sources and provenance

- [Apple HomeKit discovery implementation](https://github.com/apple/HomeKitADK/blob/master/HAP/HAPIPServiceDiscovery.c) defines model/category TXT fields and the advertised instance name. [Apple accessory categories](https://github.com/apple/HomeKitADK/blob/master/HAP/HAP.h) and the [pinned HAP-NodeJS category definitions](https://github.com/homebridge/HAP-NodeJS/blob/25e8bea26a64309a47184dec478479483fbdd50c/src/lib/Accessory.ts) provide protocol-number semantics; no upstream implementation code is incorporated.
- [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763), particularly service enumeration, instance resolution, and TXT rules.
- [Apple Bonjour Printing 1.2.1](https://developer.apple.com/bonjour/printing-specification/bonjourprinting-1.2.1.pdf), sections 9.2.6–9.2.11, for printing field semantics.
- [UPnP Device Architecture 2.0](https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0-20140901.pdf) for discovery/description structure and embedded-device identity.
- [PyChromecast discovery](https://github.com/home-assistant-libs/pychromecast/blob/8f7f3bfaa3142614b04f04e885b43e7810872adb/pychromecast/discovery.py) for Cast `md` and `fn` semantics.
- [PyChromecast model table](https://github.com/home-assistant-libs/pychromecast/blob/8f7f3bfaa3142614b04f04e885b43e7810872adb/pychromecast/const.py), imported as literal data without executing upstream code. Its MIT license is in `THIRD_PARTY_LICENSES`; the embedded JSON records commit, URL, content hash, and retrieval date. `scripts/build-cast-models.py` rebuilds it from the locally downloaded pinned source.
- [AppleDB data and MIT license](https://github.com/littlebyteorg/appledb/tree/95f799d28e45dc110ee2f25b7e3e6cf8c1124dae), the pinned source for hardware identifier candidates.
- [pyatv RAOP device-info parser](https://github.com/postlund/pyatv/blob/master/pyatv/protocols/raop/__init__.py), for the advertised `am` field.
- [pyatv AirPlay device-info parser](https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/__init__.py) for the advertised `model` field. No pyatv source or catalog is incorporated.

These mappings do not cover every model. Proprietary cloud recognition, additional discovery protocols, and broader real-device verification remain separate work.

## WS-Discovery and ONVIF scopes

Correlated WS-Discovery ProbeMatches retain endpoint references, expanded QName types, scopes, XAddrs, response message IDs, and metadata versions. Types resolve their namespace at the actual XML element, so a namespace prefix's spelling cannot establish a device type. These advertisements use protocol `ws-discovery` and service `probe-match`.

Exact `onvif://www.onvif.org/name/…` and `/hardware/…` scopes supply source-attributed `name` and `hardware` claims, with percent-decoding applied once to the path value. Multiple distinct claims remain visible. The hardware description does not automatically become a model number, manufacturer, MAC mapping, or catalog lookup. Names can populate the device name and search results. Other scope schemes/authorities/categories are preserved as metadata without an inferred identity. Query strings, fragments, user information, and decoded control text are not recognized as ONVIF scope claims.

These semantics follow section 7 of the [ONVIF Core Specification 19.12](https://www.onvif.org/specs/core/ONVIF-Core-Specification-v1912.pdf). They are device-reported discovery claims, not proof of physical hardware or ONVIF certification. Discovery sends no authentication or device-control requests; endpoint URLs are not fetched.
