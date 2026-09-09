# Configured SNMP inventory

`lantern snmp` reads device-reported inventory from one explicitly selected IPv4 or IPv6 peer. It is useful for managed routers, switches and printers with SNMP already enabled. It is a separate command and reusable `pkg/snmp` API; ordinary scan/watch profiles do not send SNMP requests.

## Run it

Set an environment variable to the device's configured read-only SNMPv2c community, then run:

```sh
lantern snmp 192.0.2.1 --community-env LANTERN_SNMP_COMMUNITY --json
lantern snmp fe80::1%en0 --community-env LANTERN_SNMP_COMMUNITY --timeout 4s
```

The example addresses are placeholders. On macOS's default zsh, enter the community without putting its value in shell history:

```zsh
read -rs 'LANTERN_SNMP_COMMUNITY?SNMP read-only community: '
echo
export LANTERN_SNMP_COMMUNITY
```

After the query, `unset LANTERN_SNMP_COMMUNITY` removes it from the shell environment. SNMPv2c carries its community and responses without encryption; use this only where that access method is appropriate. This command does not support SNMPv3, guess communities, configure devices, or send SET requests. Credentials are absent from reports and errors. The core credential wrapper redacts ordinary string, Go-syntax and JSON formatting.

`--port` defaults to UDP 161. `--timeout` is one overall deadline, defaults to two seconds, and must be positive and at most 30 seconds. A target must be one literal unicast address; hostnames, CIDRs and mapped IPv6 addresses are rejected. Link-local IPv6 needs a zone. Ctrl-C cancels collection. JSON includes a partial report and an `error` field on collection failure, with exit status 1; invalid arguments fail before collection.

## Evidence and selection

| Field | Source | Meaning |
| --- | --- | --- |
| `system.description` | `sysDescr.0`, `1.3.6.1.2.1.1.1.0` | Free-form hardware/software description; not parsed into an exact model |
| `system.object_id` | `sysObjectID.0`, `1.3.6.1.2.1.1.2.0` | Agent's object identifier; may describe software or a product family |
| `system.name` | `sysName.0`, `1.3.6.1.2.1.1.5.0` | Administratively assigned name |
| `entities[].class` | `entPhysicalClass`, `1.3.6.1.2.1.47.1.1.1.1.5.INDEX` | Physical entity class, including chassis and stack |
| Chassis `parent` | `entPhysicalContainedIn`, column 4 | Parent entity index; zero means no enclosing entity |
| Chassis `manufacturer` | `entPhysicalMfgName`, column 12 | Reported manufacturer for that chassis |
| Chassis `model` | `entPhysicalModelName`, column 13 | Reported model for that chassis |

These meanings follow [MIB-II, RFC 1213](https://www.rfc-editor.org/rfc/rfc1213.html) and [ENTITY-MIB, RFC 4133](https://www.rfc-editor.org/rfc/rfc4133.html). A vendor's enterprise-number namespace does not by itself identify a model. No SNMP model catalog is bundled.

The report promotes a chassis model only when the class walk is complete, every retained chassis has a known parent, and exactly one chassis has parent zero and a nonempty model. Its manufacturer comes from the same row. `model_oid` and `manufacturer_oid` identify the precise source fields when present. Multiple root chassis, incomplete tables, and unknown parent relationships remain unresolved. Component rows stay available even when a single device model cannot be selected. A stack member's model is not promoted to the whole stack.

All these values are device claims, not authenticated physical identities or independently verified retail names. Enabled SNMP and sufficient access are prerequisites. An unavailable field remains absent; it does not justify guessing from the name or description. A completed bounded inventory is not a completeness claim for every object the SNMP agent manages.

## Collection limits

At most three requests share a connected UDP socket and the overall deadline:

1. GET the three system fields.
2. GETBULK the physical-class column with at most 33 repetitions. Retain at most 32 entities. A valid subtree exit or end-of-MIB proves completion; a response without either remains truncated.
3. GET only parent, manufacturer and model for retained chassis, at most 96 bindings.

The third request can preserve chassis details after a truncated class walk, but truncation prevents promotion. The collector never starts a walk over the entire ENTITY-MIB subtree and never explicitly requests serial-number, hardware-ID or user/contact/location fields. GETBULK may return objects after the class column; they are used only to recognize the column's end and are not retained. It makes no retries or follow-up queries to additional addresses.

Responses must match the configured peer, community, request ID, version and response PDU. Parsing limits messages to 64 KiB, 128 bindings, 128 OID arcs and 2 KiB per value. Indefinite BER lengths, overflows, malformed values and trailing bytes fail. Valid padded definite lengths are accepted, as explicitly permitted by [RFC 3417 section 8](https://www.rfc-editor.org/rfc/rfc3417.html#section-8). Standard SNMP application types can occur after the requested column; they are decoded as bounded raw values and do not become model claims. [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html) defines the GET and GETBULK exchange semantics.

## Reusable core

```go
credentials, err := snmp.NewCredentials(configuredCommunity)
if err != nil { return err }
report, err := snmp.Read(ctx, netip.MustParseAddrPort("192.0.2.1:161"), credentials, 2*time.Second)
// Preserve report even when err != nil; earlier query evidence may be available.
```

This report has a separate schema from network scan snapshots. An [explicit offline manifest](inventory-snapshots.md) can attach saved reports to existing scan addresses and supply an opt-in inventory evaluation adapter. Automatic collection/merging in scan/watch remains future work. Physical-device accuracy and broader vendor compatibility remain unmeasured; synthetic and independent-server interoperability tests establish protocol behavior only. The published rc.7 archives predate this command.
