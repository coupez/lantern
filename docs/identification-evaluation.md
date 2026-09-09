# Measuring identification accuracy

`lantern evaluate` scores saved observations against an independently labeled device list. It runs offline and uses no recognition catalogs. Its inputs and results can be shared by applications through `pkg/evaluation`.

Start with the deliberately [synthetic truth](../examples/identification/truth.json), [scan](../examples/identification/scan.json) and [address bindings](../examples/identification/bindings.json):

```sh
./bin/lantern evaluate --truth examples/identification/truth.json \
  --scan examples/identification/scan.json \
  --bindings examples/identification/bindings.json
```

Add `--json` for every case outcome, class/state breakdowns, exact input SHA-256 hashes and scan duration. These fixture scores are arithmetic examples, not physical-device accuracy measurements. The example has five labeled cases, four observed devices and three responsive devices. Two addresses map to the same printer; conflicting retail names yield an ambiguous result.

Saved Android/SNMP attachments are ignored by default. With `--scan`, add `--include-inventory` to union their reported-model claims with network model predictions. Conflicts remain ambiguous, retail/type fields and presence counts are unchanged, the system becomes `lantern+inventory`, and duration is omitted because inventory collection is not timed by the scan. See [attachment provenance and example](inventory-snapshots.md).

## Prepare a physical benchmark

Create the truth file before examining either scanner's predictions. Set `kind` to `physical`, choose a stable dataset `id`, and include every independently known device within the chosen scope, including devices that may be missed. A case has a stable `id`, a `class`, a list of `states`, and independently known `truth` fields. For example:

```json
{
  "id": "printer-a",
  "class": "printer",
  "states": ["awake", "wired"],
  "truth": {
    "reported_model": {
      "accepted": ["Laser42"],
      "source_kind": "physical_label",
      "source": "Model code on the product label"
    },
    "retail_model": {
      "accepted": ["Example Laser 42"],
      "source_kind": "purchase_record",
      "source": "Verified purchase record for this device"
    },
    "kind": {
      "accepted": ["printer"],
      "source_kind": "manual_verification",
      "source": "Physical inspection"
    }
  }
}
```

`accepted` values must be independently verified aliases for **one fact**, not every product in a recognizer's candidate list. Values must be valid UTF-8 without controls, format characters or the Unicode replacement character. Matching is exact and case-sensitive: there is no case folding, punctuation repair, fuzzy matching or catalog expansion. List verified spelling aliases explicitly. Omit unknown truth fields; an absent label is unassessed, not evidence that a prediction is wrong.

Every supplied field requires a nonempty provenance note and one of `physical_label`, `settings`, `authorized_inventory`, `purchase_record`, `manufacturer_record` or `manual_verification`. `synthetic` is allowed only in synthetic datasets. This records the stated source; software cannot prove that an author's labels are independent or correct.

Each run must name the same dataset ID. Record tool version, vantage point, profile, device state and collection timing in the run/bindings metadata. Comparable scores require equivalent scope and conditions; matching dataset IDs alone does not establish comparability. Use separate datasets for changed device states or cohorts.

## Map observations without using their predictions

The bindings file maps exact native IP addresses to case IDs. Obtain these associations independently, such as from a controlled test network or an owner's address settings. Include expected addresses even when the scan misses them. IPv6 link-local addresses need an explicit zone. Never join records by guessed names, MAC vendor, or predicted models.

Multiple addresses may intentionally map to one case. The evaluator takes the union of all seen predictions for that case, preserving conflicting values. It never selects whichever address produced the best answer. Extra mapped records are reported as fragmentation and do not increase the device denominator.

For Lantern snapshots, the adapter uses only the selected `identity.model` as `reported_model`, all `identity.model_names` as `retail_model`, and the reported `kind`. Generic `device`/`unknown` kinds abstain. A raw model string is not automatically a retail name. MAC vendors, banners and alternate identity claims are not promoted into evaluated model assertions. Thus this measures the selected output a user receives, while snapshots retain the original evidence for diagnosis.

A cached neighbor counts as observed but does not count as responsive without active discovery or local-interface evidence. Unmapped scan addresses remain an explicit **unassessed** list. They may be unexpected devices, incomplete labels or out-of-scope records; they are not automatically false positives. Duplicate addresses within one run are rejected rather than silently reassigned.

## Normalize another scanner's results

Use the same independent truth with a [normalized run](../examples/identification/normalized-run.json):

```sh
./bin/lantern evaluate --truth examples/identification/truth.json \
  --run examples/identification/normalized-run.json --json
```

The example's system is `example-scanner`; it is not a Fing measurement. To compare Fing, preserve its original output privately, then transcribe its observed rows into the same schema with `system: "fing"`, the actual version, source reference, context and explicit case IDs. If the scanner explicitly labels a result as a family, place it only in the separate `family` candidate field and preserve that label verbatim; leave exact-model fields empty unless the source makes a separate model assertion. Optional independent `family` truth labels use the same provenance and scoring rules. The Lantern adapter currently has no explicit family field to extract. Preserve all candidates supplied for one field. Use `seen` and `responsive` only when supported by the original observation; a cached/offline entry does not establish responsiveness. No native Fing export parser is currently provided.

## Read the scores

Each field receives exactly one outcome per case:

| Outcome | Meaning |
| --- | --- |
| `unlabeled` | No independent truth for this field; excluded from accuracy denominators |
| `missed` | Truth exists but no mapped record was seen |
| `unknown` | Device seen, field labeled, no prediction supplied |
| `correct` | Every predicted candidate is an accepted alias for the verified fact |
| `ambiguous` | Predictions include both an accepted and an unaccepted value |
| `incorrect` | Predictions are nonempty and none match the verified fact |

A multiple-candidate set containing no correct value is incorrect. Multiple verified aliases for one product can be correct; multiple distinct products should never be declared equivalent in truth.

- **Precision** = correct / (correct + ambiguous + incorrect). A prediction that includes the right model among wrong alternatives is not an exact success.
- **Recall** = correct / labeled cases. Missed, unknown, ambiguous and incorrect cases remain in this denominator.
- **Observed recall** = observed cases / all cases. Responsive recall is reported separately.
- A zero denominator is `null` in JSON and `n/a` in text, never 0% or 100%.

`reported_model` tests the exact observed model code/text against its own labels; it is not automatically an exact retail-model score. `retail_model` scores the separately named catalog candidates. `family` scores explicitly declared family labels and `kind` scores type labels. Family-only predictions do not count as exact-model assertions. A model code shared by several retail variants cannot establish which variant is present.

Class and state breakdowns use the same rules. State slices may overlap; do not add their counts or average them into a new overall score. Scan duration is retained separately from evaluator execution time. Packet counts, memory and time to first identity are not measured by this command.

Partial/cancelled/error scans retain their incomplete status and still receive scores, including misses. Do not silently exclude a failed run when comparing tools. Warnings remain in JSON. A score alone does not establish physical-device coverage, a representative sample, or statistical significance.

## Reproducibility and bounds

Inputs must be regular JSON files, each at most 16 MiB. Duplicate object keys, trailing documents, invalid schema values, unsupported fields in benchmark inputs and excessive nesting are rejected. Saved scanner reports may carry extra fields for schema-1 compatibility. The core bounds dataset/observation counts and candidate lists, validates scoped addresses and provenance, and returns independently owned results.

The CLI hashes the exact bytes of every input. Keep those files alongside the result; the hashes identify inputs but do not certify their truth. No scan is run and no file is modified by evaluation. Keep machine-specific scans, mappings and physical labels local unless you explicitly choose to share them.
