"""The laboratory run: expected pattern, written outputs and trace content.

The laboratory is run once into a temporary folder (real HTTP on 127.0.0.1).
"""
import glob
import json
import os
import re
import shutil
import tempfile
import unittest

from sesstrace.lab import verify
from sesstrace.lab.mechanisms import MECHANISMS, load_metadata
from sesstrace.lab.runner import run, run_scenario
from sesstrace.lab.servers import Flags

SECRET_PATTERN = re.compile(r"[0-9a-f]{16,}|eyJ[A-Za-z0-9_-]{10,}")
EXPECTED_IDS = ["M1", "M2", "M3", "M4", "M5", "M6"]


class BenchmarkPattern(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sesstrace-")
        cls.results = run(cls.tmp, quiet=True)
        cls.rows = {row["id"]: row for row in cls.results["mechanisms"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_all_mechanisms_present(self):
        self.assertEqual(sorted(self.rows), EXPECTED_IDS)
        self.assertEqual(self.results["summary"]["n_scenarios"], 12)

    def test_pov_fails_invariant_on_every_vulnerable_variant(self):
        for mechanism in EXPECTED_IDS:
            scenario = self.rows[mechanism]["vulnerable"]
            with self.subTest(mechanism=mechanism):
                self.assertTrue(scenario["termination_reported_success"])
                self.assertEqual(scenario["replay_status"], 200)
                self.assertEqual(scenario["invariant"], "FAIL")
                self.assertTrue(scenario["pov_confirmed"])

    def test_pof_passes_invariant_on_every_fixed_variant(self):
        for mechanism in EXPECTED_IDS:
            scenario = self.rows[mechanism]["fixed"]
            with self.subTest(mechanism=mechanism):
                self.assertTrue(scenario["termination_reported_success"])
                self.assertIn(scenario["replay_status"], (400, 401))
                self.assertEqual(scenario["invariant"], "PASS")
                self.assertTrue(scenario["pof_confirmed"])

    def test_zero_negative_control_failures(self):
        for mechanism in EXPECTED_IDS:
            for variant in ("vulnerable", "fixed"):
                scenario = self.rows[mechanism][variant]
                with self.subTest(mechanism=mechanism, variant=variant):
                    for name, check in scenario["negatives"].items():
                        self.assertTrue(check["pass"], "%s %s negative %s observed %s"
                                        % (mechanism, variant, name, check["observed"]))
                    self.assertEqual(scenario["negative_control_failures"], 0)
        self.assertEqual(self.results["summary"]["negative_control_failures"], 0)
        self.assertTrue(self.results["summary"]["all_clean"])

    def test_outputs_written(self):
        for name in ("benchmark_results.json", "benchmark_matrix.csv", "artifact_inventory.csv"):
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, name)), name)
        self.assertEqual(len(glob.glob(os.path.join(self.tmp, "traces", "*.json"))), 12)

    def test_traces_contain_required_fields_and_no_secrets(self):
        for path in glob.glob(os.path.join(self.tmp, "traces", "*.json")):
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIsNone(SECRET_PATTERN.search(text), "secret-looking value in " + path)
            trace = json.loads(text)
            for key in ("mechanism", "variant", "artifact_inventory", "termination", "steps",
                        "replay", "invariant", "cwe_rule_path", "uncertainty"):
                self.assertIn(key, trace, path)
            self.assertIn(trace["uncertainty"]["level"], ("low", "medium", "high"))
            self.assertTrue(trace["termination"]["declared_expected_scope"])
            for step in trace["steps"]:
                for key in ("step", "actor", "method", "host", "path", "status", "artifact_presented"):
                    self.assertIn(key, step)
            for artifact in trace["artifact_inventory"]:
                for key in ("id", "type", "holder", "issued_at_step"):
                    self.assertIn(key, artifact)
            expected = "FAIL" if trace["variant"] == "vulnerable" else "PASS"
            self.assertEqual(trace["invariant"]["result"], expected, path)

    def test_declared_metadata_matches_code(self):
        meta = load_metadata()
        self.assertEqual(sorted(meta), EXPECTED_IDS)
        self.assertEqual([mechanism.id for mechanism in MECHANISMS], EXPECTED_IDS)
        for mechanism in EXPECTED_IDS[:5]:
            self.assertEqual(meta[mechanism]["paper_class"], "A")
            self.assertEqual(meta[mechanism]["lifecycle_family"], "explicit_termination")
        self.assertEqual(meta["M6"]["paper_class"], "B")
        self.assertEqual(meta["M6"]["lifecycle_family"], "adjacent_withdrawal")

    def test_runtime_rule_path_respects_paper_class(self):
        meta = load_metadata()
        by_id = {mechanism.id: mechanism for mechanism in MECHANISMS}
        _, first = run_scenario(by_id["M1"], "vulnerable", meta["M1"])
        _, sixth = run_scenario(by_id["M6"], "vulnerable", meta["M6"])
        self.assertIn("paper class A", first["cwe_rule_path"]["classification"])
        self.assertIn("paper class B", sixth["cwe_rule_path"]["classification"])
        self.assertIn("adjacent-authority withdrawal", sixth["cwe_rule_path"]["classification"])

    def test_traces_equal_the_reference_traces(self):
        same = verify.compare_traces(os.path.join(self.tmp, "traces"))
        self.assertEqual(len(same), 12)
        self.assertTrue(all(same.values()), [name for name, equal in same.items() if not equal])


class Determinism(unittest.TestCase):
    def test_same_seed_same_trace(self):
        meta = load_metadata()
        mechanism = MECHANISMS[0]
        _, first = run_scenario(mechanism, "vulnerable", meta[mechanism.id])
        _, second = run_scenario(mechanism, "vulnerable", meta[mechanism.id])
        self.assertEqual(first, second)


class FlagsTest(unittest.TestCase):
    def test_unknown_flag_rejected(self):
        with self.assertRaises(ValueError):
            Flags(vulnerable={"M9"})

    def test_membership(self):
        self.assertIn("M3", Flags(vulnerable={"M3"}))
        self.assertNotIn("M3", Flags())


if __name__ == "__main__":
    unittest.main()
