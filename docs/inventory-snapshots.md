# Attach saved inventory to a network scan

`lantern enrich` attaches saved Android or SNMP reports to explicitly chosen addresses already present in a scan. It runs offline. Inventory remains in each device's separate `inventory` field, alongside the original network observations.

Try the complete synthetic example from a source checkout:

```sh
./bin/lantern enrich --scan examples/identification/scan.json \
  --inventory examples/identification/inventory.json \
  --save /tmp/lantern-example-enriched.json --details
```

The example supplies a phone's reported model and a router claim that conflicts with its network model. These are hand-authored fixtures, not measurements of actual devices. Add `--json` to print the enriched schema-1 snapshot.

## Use your own observations

Save your network scan with `lantern scan --profile deep --save scan.json`. Collect a selected phone through the [Android command](android-inventory.md), or a configured device through the [SNMP command](snmp-inventory.md), with `--json` redirected into a separate file. Create a manifest:

```json
{
  "schema": 1,
  "bindings": [
    {
      "id": "phone-observation",
      "kind": "android",
      "path": "android.json",
      "addresses": ["192.0.2.7"]
    },
    {
      "id": "switch-observation",
      "kind": "snmp",
      "path": "snmp.json",
      "observed_at": "2026-09-09T12:00:00Z",
      "addresses": ["192.0.2.8"]
    }
  ]
}
```

Replace the example addresses and timestamp with independently confirmed values. Source paths resolve relative to the manifest. Every address must exactly match an existing scan entry, including an IPv6 interface zone. One observation may be explicitly associated with several addresses; the importer does not discover these associations or merge their device records. An ADB transport handle is not a LAN address or permanent device ID. A saved SNMP target also does not establish that an address still belongs to the same device in a later scan.

Android uses its collector's `collected_at` timestamp; an optional manifest timestamp must match it exactly. SNMP reports currently have no collection timestamp, so `observed_at` is required and recorded as `owner-supplied`. No automatic freshness threshold is applied. Retain the scan and collection times when assessing whether a binding remains appropriate.

Run `lantern enrich --scan scan.json --inventory inventory.json --save enriched.json --details`. The importer reconstructs claims from raw validated source fields. Android's precomputed claims are ignored; SNMP's selected chassis is independently recomputed and inconsistent derived fields are rejected. System descriptions and enterprise OIDs do not become model guesses. Partial SNMP component evidence remains visible without promotion to a selected model. Failed Android reports cannot contribute property claims.

Each attachment records its ID, kind, source, timestamp/time basis, status, bound address, exact field keys/references, and SHA-256 hashes of the source file and complete manifest. Hashes identify input bytes; they do not authenticate hardware or the owner's binding. Preserve the original files if you need to reproduce the import.

Reimporting the same ID and identical content is idempotent. Changing an existing ID's content is rejected; reapply the new manifest to the original scan. Different IDs retain separate observations and conflicting model values. Input validation completes before a saved output is replaced.

## Display and evaluation

Compact output adds a labeled inventory model line; details show every observation and claim. Existing network names, vendor and selected identity retain display priority. Inventory can provide a labeled fallback when those are absent. Inventory does not change type hints, scan timing, discovery counters, responsiveness, or network-change events. A cached neighbor remains a cached neighbor.

The default evaluator ignores inventory. Include it explicitly:

```sh
./bin/lantern evaluate --truth examples/identification/truth.json \
  --scan /tmp/lantern-example-enriched.json \
  --bindings examples/identification/bindings.json --include-inventory --json
```

This labels the system `lantern+inventory`, takes the union of network and inventory reported-model claims, and preserves ambiguity. It does not infer retail models or types. Scan duration is omitted because it excludes inventory collection. Compare inventory-assisted results with equivalently assisted results; see [evaluation semantics](identification-evaluation.md). The synthetic example remains four observed and three responsive devices out of five cases.

## Core and bounds

`pkg/inventory.FromAndroid` and `FromSNMP` convert source reports with input metadata into unbound `scanner.InventoryObservation` values. `inventory.Apply` accepts these values and explicit address bindings, returning an independently mutable report. `scanner.ValidateSnapshot`, Save/Load and `Device.Clone` validate or preserve the namespace. `evaluation.FromLanternWithInventory` is the opt-in evaluation adapter.

The CLI reads regular JSON files only, rejects duplicate keys, unknown fields, invalid UTF-8, trailing documents and excessive nesting, and limits each manifest/source to 1 MiB and the scan to 16 MiB. A manifest has at most 128 bindings and 32 addresses per binding. Snapshots allow eight observations per device, 2,048 total and 4 MiB of claim text. Each observation allows 72 claims, each value at most 2,048 bytes. The importer performs no network requests or credential handling. Automatic inventory collection in scan/watch remains future work; rc.7 archives predate this command.
