"""The expiration fixtures M7 (idle lifetime) and M8 (absolute lifetime)."""
import json
import unittest

from sesstrace.lab import expiry, verify


class ExpirationFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = expiry.run()

    def test_all_four_http_contracts(self):
        summary = self.results["summary"]
        self.assertTrue(summary["all_clean"])
        self.assertEqual(summary["n_scenarios"], 4)
        self.assertEqual(summary["n_http_steps"], 36)
        self.assertEqual(summary["controls_passed"], 12)

    def test_exact_boundaries(self):
        for row in self.results["scenarios"]:
            self.assertEqual(row["boundary_s"], 19 if row["mode"] == "idle" else 10)
            self.assertEqual(row["replay_status"], 401 if row["variant"] == "fixed" else 200)
            self.assertEqual(row["paper_class"], "T")

    def test_idle_resets_absolute_does_not(self):
        for mode in expiry.MODES:
            fixture = expiry.Fixture(mode, True)
            token = fixture.login("alice")
            fixture.now = 9
            self.assertEqual(fixture.access(token)[0], 200)
            fixture.now = 10
            self.assertEqual(fixture.access(token)[0], 200 if mode == "idle" else 401)

    def test_missing_token_not_expiration(self):
        fixture = expiry.Fixture("absolute", True)
        fixture.now = 100
        self.assertEqual(fixture.access("unknown"), (401, {"error": "missing_artifact"}))

    def test_repeatable_traces_and_no_serialized_credentials(self):
        again = expiry.run()
        self.assertEqual(again, self.results)
        text = json.dumps(again)
        self.assertNotIn("synthetic-alice", text)
        self.assertNotIn("Bearer ", text)
        self.assertNotIn("127.0.0.1", text)

    def test_result_equals_the_reference_result(self):
        with open(str(verify.REFERENCE_DIR / "expiry_results.json"), encoding="utf-8") as handle:
            self.assertEqual(self.results, json.load(handle))

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            expiry.Fixture("sliding", True)


if __name__ == "__main__":
    unittest.main()
