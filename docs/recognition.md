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
| `_hap._tcp` (HomeKit) | `md` model, instance name, `ci` category | Advertised name/model plus source-linked protocol category interpretation |
| `_googlecast._tcp` | `md`, `fn` | Advertised model and friendly name |
| Pinned PyChromecast catalog | 40 exact Cast model → manufacturer mappings | Catalog-derived, explicitly labeled |
| SSDP → UPnP description | `friendlyName`, `manufacturer`, `modelName`, `modelNumber`, `deviceType`, `UDN` | Device-reported XML; embedded devices stay distinct |

The `identity` object offers selected name/manufacturer/model/firmware fields, plus all recognized claims and their provenance. The advertised `model` remains unchanged. `model_names` contains unique, sorted catalog candidates for that selected model; one candidate is a catalog interpretation, and several candidates indicate unresolved variants. Each catalog claim records the exact input identifier and pinned source-file URL. Explicit standardized fields precede printer display descriptions; catalog-derived manufacturer claims rank below device-reported manufacturer fields. Ties are resolved deterministically by source/key/value, not packet arrival order. Catalog names and manufacturers attach only to the selected model claim; metadata from a conflicting, unselected model cannot silently populate the selected identity. Conflicting claims remain visible. A claim is not an authenticated hardware identity.

The CLI shows identity fields in `inspect` / `--details`; JSON and saved snapshots retain claims and raw advertisements. CSV includes reported-name, manufacturer, model, model-candidate, firmware, and firmware-version columns. The two firmware columns are appended after `model_candidates`; earlier column positions stay the same.

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

mDNS and SSDP each process at most 512 received datagrams, including ignored/malformed traffic. mDNS also caps query attempts at 128, including initial questions and follow-ups. Reaching either limit adds a completeness warning while retaining decoded observations. A query limit stops new questions but allows pending replies to arrive within the existing response window. Unexpected receive errors and query/short-write failures also retain already-decoded data and add a warning. Normal read-deadline expiry and cancellation do not become socket-failure warnings. SSDP multicast hop-limit setup errors are reported before querying.

UPnP description requests only accept HTTP URLs with a literal IP matching the SSDP responder. The transport pins that address and disables proxies and redirects. Four unique URLs share one per-device timeout. Response headers, body size (256 KiB), XML depth (32), device count (64), and field lengths are bounded. The USN's device UUID is matched to the description's UDN before attaching a model, so an embedded device does not silently inherit the root device's identity. Unknown, malformed, inaccessible, or unmatched descriptions leave the original SSDP advertisement intact.

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
