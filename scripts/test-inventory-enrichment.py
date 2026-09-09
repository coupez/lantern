#!/usr/bin/env python3
"""Offline compiled-CLI checks for explicitly bound inventory enrichment."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) > 2:
    raise SystemExit(f"usage: {Path(sys.argv[0]).name} [LANTERN_BINARY]")
SCRIPT_ROOT = Path(__file__).resolve().parents[1]
ROOT = SCRIPT_ROOT if (SCRIPT_ROOT / "examples" / "identification").is_dir() else Path.cwd()
BIN = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "bin" / "lantern"
sys.argv = sys.argv[:1]
EXAMPLES = ROOT / "examples" / "identification"
RESPONSIVE_EVIDENCE = {"arp", "ndp", "icmp", "tcp-open", "tcp-refused", "mdns", "ssdp", "ws-discovery", "netbios", "local-interface"}


def responsive(device):
    return bool(RESPONSIVE_EVIDENCE.intersection(device.get("evidence", [])))


class InventoryEnrichmentCLI(unittest.TestCase):
    def run_cli(self, *args):
        process = subprocess.run([str(BIN), *map(str, args)], capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        return process

    def test_enrich_snapshot_and_evaluation_boundaries(self):
        scan = EXAMPLES / "scan.json"
        manifest = EXAMPLES / "inventory.json"
        truth = EXAMPLES / "truth.json"
        bindings = EXAMPLES / "bindings.json"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            enriched = directory / "enriched.json"
            reimported = directory / "reimported.json"
            result = self.run_cli("enrich", "--scan", scan, "--inventory", manifest, "--save", enriched, "--json")
            rendered = json.loads(result.stdout)
            saved = json.loads(enriched.read_text())
            self.assertEqual(rendered, saved)

            original = json.loads(scan.read_text())
            self.assertEqual({k: v for k, v in saved.items() if k != "devices"}, {k: v for k, v in original.items() if k != "devices"})
            self.assertEqual(len(saved["devices"]), len(original["devices"]))
            for before, after in zip(original["devices"], saved["devices"]):
                for key, value in before.items():
                    self.assertEqual(after.get(key), value, key)
                # Go's zero-value Vendor struct is serialized by scanner.Save;
                # it is metadata normalization, not an inventory-side change.
                self.assertEqual(set(after) - set(before) - {"inventory", "vendor"}, set())
                if "vendor" in after:
                    self.assertEqual(after["vendor"], {"private": False, "multicast": False})
                self.assertEqual(responsive(before), responsive(after))

            source_hash = {
                "synthetic-phone": hashlib.sha256((EXAMPLES / "android.json").read_bytes()).hexdigest(),
                "synthetic-router": hashlib.sha256((EXAMPLES / "snmp.json").read_bytes()).hexdigest(),
            }
            binding_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
            attached = {
                observation["id"]: observation
                for device in saved["devices"]
                for observation in device.get("inventory", [])
            }
            self.assertEqual(set(attached), set(source_hash))
            for identifier, observation in attached.items():
                self.assertEqual(observation["source_sha256"], source_hash[identifier])
                self.assertEqual(observation["binding_sha256"], binding_hash)

            # inventory.json refers to android.json and snmp.json relatively.
            self.run_cli("enrich", "--scan", enriched, "--inventory", manifest, "--save", reimported, "--json")
            self.assertEqual(json.loads(reimported.read_text()), saved)
            self.assertEqual(json.loads(self.run_cli("diff", enriched, reimported).stdout), [])

            base_args = ("evaluate", "--truth", truth, "--scan", scan, "--bindings", bindings, "--json")
            default = json.loads(self.run_cli(*base_args).stdout)["evaluation"]
            enriched_default = json.loads(self.run_cli("evaluate", "--truth", truth, "--scan", enriched, "--bindings", bindings, "--json").stdout)["evaluation"]
            self.assertEqual(enriched_default["overall"], default["overall"])

            assisted = json.loads(self.run_cli("evaluate", "--truth", truth, "--scan", enriched, "--bindings", bindings, "--include-inventory", "--json").stdout)["evaluation"]
            self.assertEqual(assisted["system"], "lantern+inventory")
            self.assertNotIn("duration_ms", assisted)
            overall = assisted["overall"]
            self.assertEqual((overall["observed"], overall["responsive"]), (4, 3))
            reported = overall["fields"]["reported_model"]
            self.assertEqual(tuple(reported[key] for key in ("correct", "incorrect", "ambiguous", "unknown", "missed", "unlabeled")), (2, 0, 1, 0, 1, 1))
            self.assertEqual(overall["fields"]["retail_model"], default["overall"]["fields"]["retail_model"])

            details = self.run_cli("enrich", "--scan", scan, "--inventory", manifest, "--details").stdout
            for value in ("adb://127.0.0.1:5037/transport/1", "snmpv2c://192.0.2.4:161", "ro.product.model", "1.3.6.1.2.1.47.1.1.1.1.13.1", binding_hash):
                self.assertIn(value, details)


if __name__ == "__main__":
    unittest.main()
