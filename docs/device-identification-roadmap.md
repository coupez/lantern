# Device identification: exploration and implementation plan

Updated 2026-09-09. The expanded objective is to match or exceed Fing on **measured identification accuracy and useful coverage**, while preserving Lantern's fast CLI and reusable core. Fing's advertised 450K device models is a catalog benchmark, not a promised number of distinguishable LAN targets. Publication remains authorized. The service/GUI is outside this implementation phase.

## Parallel exploration and selection

Three separately scoped agents explored the problem using different models: Luna surveyed catalogs, Sol surveyed fingerprinting techniques, and Terra assessed code feasibility. The parent read their reports, checked the selected techniques against primary implementation/documentation and current code, and implemented the combined result. An independent follow-up review checked the implementation.

The first implementation adds two evidence channels without importing a new catalog:

| Selected change | Concrete improvement | Evidence boundary |
| --- | --- | --- |
| Companion DNS-SD | Directly request `_companion-link._tcp`; interpret its `rpMd` model identifier through the existing AppleDB catalog | pyatv demonstrates this field for Apple TV. Mac/phone model exposure is not established; our retained Mac scans contained Companion records without this key |
| Roku ECP | Request `roku:ecp` through SSDP, then read the advertised endpoint's fixed `/query/device-info` path | A responding device supplies its model/name/vendor/software fields. No promise of coverage when discovery or the endpoint is unavailable |

Primary evidence: [pinned pyatv Companion implementation](https://github.com/postlund/pyatv/blob/b277a4c8222ecdcbaab8a24e3e713ca44765adb4/pyatv/protocols/companion/__init__.py), [Roku ECP specification](https://developer.roku.com/dev/docs/external-control-api). Detailed behavior and checks are in [recognition](recognition.md#companion-model-recognition) and [verification](verification.md#companion-and-roku-identification).

These changes increase the information used from eligible devices. They do not increase the embedded model-catalog count or establish a physical-device accuracy percentage. The rc.7 release archives predate them.

## Next experiments, in priority order

| Approach | Observable input and useful output | Decision |
| --- | --- | --- |
| DHCP/DHCPv6 capture import | Ordered options, request lists, vendor classes and names can support OS/family candidates despite private MAC addresses | Implemented bounded offline PCAP/PCAPNG import and optional explicit single-packet Fingerbank classification with local payload preview. No classifier bundled or provider labels promoted to measured models. Next: labeled provider evaluation and passive live/router collection; see [capture](dhcp-observations.md) and [cloud lookup](fingerbank-lookup.md) |
| IPP printer identity | Get-Printer-Attributes can supply printer make/model beyond sparse Bonjour TXT | Implemented bounded IPP/IPPS queries from discovered port/resource paths, selected identity fields and endpoint-scoped claims. Synthetic IPv4/IPv6/TLS fixtures validate collection; physical printer coverage remains unmeasured |
| ONVIF camera identity | GetDeviceInformation can supply manufacturer, model and firmware beyond discovery scopes | Implemented bounded SOAP 1.2 reads from qualifying same-device discovery endpoints, with endpoint-linked manufacturer/model/firmware and discarded serial/hardware IDs. Protected devices remain discovery-only; credentialed reads and physical compatibility remain future work |
| Authorized host inventory / user confirmation | Mac hardware model, managed Apple model identifier, or an owner's phone model selection | Implemented local Mac kernel-model collection on selected local IPv4/IPv6 addresses, with AppleDB candidates and source precedence. An explicit Android ADB property collector is also implemented. Explicit saved Android/SNMP inventory-to-snapshot bindings and separate assisted evaluation are implemented. Managed Apple imports and owner confirmation remain future work |
| Configured SNMP inventory | System scalars and bounded ENTITY-MIB chassis manufacturer/model | Implemented explicit single-peer `snmp` command and reusable core with configured v2c access, source OIDs and conservative chassis selection. No inferred model from PEN or sysDescr; explicit offline attachment is implemented; automatic scan/watch collection, SNMPv3 and physical compatibility remain future work. See [inventory limits](snmp-inventory.md) |
| Android retail-name aliases | Manufacturer/model/codename supplied by a device API or inventory | Collector now exists; revisit after data provenance/reuse terms are established; wrapper license alone does not settle source-data terms |
| TCP-stack signatures | Initial packet options, windows and quirks | Potential OS/family evidence; substantial collection/matching work, ambiguous modern stacks, and source-specific data terms. Lower priority than explicit model fields |
| Zigbee/Matter bridge inventory | Coordinator-reported manufacturer/model/cluster identifiers | Optional bridge adapter. An IP scanner cannot count every bridge child as a directly scanned LAN device |

DHCP fingerprinting is explicitly addressed by [RFC 7844](https://www.rfc-editor.org/rfc/rfc7844.html): request lists and other options can reveal implementation differences, while privacy profiles reduce those signals. This supports collecting the evidence, not assuming that two phones with the same network stack have distinct fingerprints.

Protocol and inventory references: [IPP Get-Printer-Attributes, RFC 8011](https://www.rfc-editor.org/rfc/rfc8011.html#section-4.2.5), [ONVIF Core specification](https://www.onvif.org/specs/2306/ONVIF-Core-Spec-v2306.pdf), [Apple managed model identifier](https://developer.apple.com/documentation/devicemanagement/statusdevicemodelidentifier), [IANA enterprise numbers](https://www.iana.org/assignments/enterprise-numbers/).

Catalog leads remain research inputs: [Fingerbank](https://www.fingerbank.org/), [Nmap OS detection](https://nmap.org/book/man-os-detection.html), [AndroidDeviceNames](https://github.com/jaredrummler/AndroidDeviceNames), [Zigbee Herdsman definitions](https://github.com/Koenkk/zigbee-herdsman-converters/tree/master/src/devices). No new rows from these projects are embedded by this change. Initial scout figures and licensing summaries require pinned-source verification before any import; historical data and mirrors are not current-coverage measurements.

## How to establish an improvement

The offline `lantern evaluate` command and reusable `pkg/evaluation` core now provide scoring and an explicit Lantern snapshot adapter. See [schema, synthetic examples and denominators](identification-evaluation.md). Physical labels and comparable Fing runs remain required.

Create a labeled device matrix with independently known manufacturer, hardware code, retail-model variants and OS. Include Macs, iPhones, Android phones, printers, routers, cameras, media players and IoT devices, and vary awake/asleep state, advertised services, private MAC settings and network visibility.

Measure separately:

- Discovery coverage: known in-scope devices observed, including explicit missed devices.
- Exact-model precision: correct exact model assertions divided by all exact model assertions.
- Exact-model recall: correct exact assertions divided by labeled in-scope devices; report undiscovered devices too.
- Family/type accuracy, ambiguity rate and unknown rate, without counting them as exact models.
- Time to first useful identity, complete-scan duration, packets/connections and memory.

Compare Lantern and Fing under equivalent device state and network vantage. Preserve both raw observations and expected labels so a catalog update cannot manufacture its own ground truth. Report per-class and per-state results; an aggregate score can hide weak phone coverage. Add sources only when their matching input is collected or an explicit inventory import can supply it.

## Persistent work rules

Keep the objective active while independent work remains. Physical-device checks and unavailable proprietary datasets constrain specific claims, but do not prevent collector, catalog, fixture or measurement work. Carry promising ideas through implementation and tests. Retain source provenance and conflicting candidates; never label guesses as measured facts or catalog size as recognition success.

## Follow-up exploration: phones and host inventory

The second lightweight exploration checked existing parsers before proposing new work. AirPlay/device-info `model`, RAOP `am`, Cast `md`/`fn`, Companion `rpMd` and local Mac `hw.model` are already collected where available. Their presence in a parser does not establish that a particular Mac or phone advertises a model in its current state.

The strongest next implementation candidate is explicit owner-authorized Android inventory. Android defines `Build.MANUFACTURER`, `MODEL`, `DEVICE` and `FINGERPRINT` as manufacturer, user-facing model, industrial-design identifier and build identifier respectively. These are separate evidence fields: the build fingerprint is software evidence, not a retail-model label. [Android Build API](https://developer.android.com/reference/android/os/Build).

An ADB-backed collector requires a deliberately authorized device connection. ADB supports host/device communication and shell commands; it is not general LAN discovery. A bounded import of those selected properties, with an explicit inventory/address binding, would be a useful first step. Rooted or customized devices can change reported properties, so this would still be attributed inventory evidence. [Android ADB documentation](https://developer.android.com/tools/adb). The subsequent Android change implements the native ADB collector through an existing local server and one selected transport. It requests only four allowlisted properties and retains exact source keys; no Android catalog is bundled. See [usage and boundaries](android-inventory.md).

For managed Apple devices, Apple exposes a model identifier through device-management status. A future owner-supplied export adapter can map that identifier through AppleDB while retaining its management source and explicit device binding. An ordinary network scan has no equivalent access to that status. [Apple managed model identifier](https://developer.apple.com/documentation/devicemanagement/statusdevicemodelidentifier).

Physical validation of existing Apple discovery remains a parallel priority: compare awake/asleep Macs, iPhones, iPads and Apple TVs with independently known model labels, advertised-service states and private-MAC settings. Additional catalog entries cannot resolve a missing distinguishing observation. These priorities are engineering judgments from the cited interfaces and current collector coverage; they are not claims of measured improvement over Fing.

## Inventory integration and vendor discovery

The shared explicit inventory-to-snapshot adapter is implemented: owner-selected canonical scoped IP bindings preserve competing network claims and source/timestamp provenance without changing network responsiveness. Inventory-assisted evaluation remains separate; see [usage](inventory-snapshots.md).

The next protocol comparison considered Ubiquiti UDP discovery and TP-Link Kasa/Tapo. Ubiquiti is implemented as an opt-in finite-target IPv4 pass with dedicated model TLVs and bounded v1/v2 requests. Platform and firmware-build strings remain separate from models. Kasa's legacy UDP/9999 interface is useful, but modern support also requires evaluating UDP/20002 and newer discovery variants rather than assuming that the legacy path covers all Kasa/Tapo devices. [Pinned python-kasa discovery implementation](https://github.com/python-kasa/python-kasa/blob/a29d0610bacd084a2197a7025cf083d4d2a51b02/kasa/discover.py), [Ubiquiti behavior](ubiquiti-discovery.md).

Android catalog review still found Google-derived data in AndroidDeviceNames and public model-list mirrors without establishing independent redistribution terms. Keep those rows out of the bundled catalog until reuse terms are established; an explicit owner-supplied catalog adapter remains useful future work. This is an unresolved source-provenance question, not evidence that model aliases cannot improve authorized inventory matching.
