"""The driver and the evaluator on the plans of the four library targets, against stub servers.

The plans and expectations are the ones of the published checks; only the
waits are shortened. The stubs behave as each library does at its two
revisions, or deviate in one chosen way.
"""
import unittest

from tests import scenarios
from tests.stubs import SessionStub

# How each library keeps its sessions, as far as the plans can tell.
KIND = {"T1": "store", "T2": "stateless", "T3": "stateless", "T4": "pool"}


def library_stub(entry, variant, repairs=True, **options):
    target = entry.get("target", entry["id"])
    options.setdefault("slow", entry.get("slow_seconds", 1.0))
    return SessionStub(KIND[target], variant == "fixed" and repairs, entry.get("lifetime_seconds", 1), **options)


class SingleRuns(unittest.TestCase):
    """One run per target and revision (the first two series of the checks)."""

    @classmethod
    def setUpClass(cls):
        cls.first = scenarios.shortened(scenarios.load("EXTERNAL_SPEC.json"))
        cls.second = scenarios.shortened(scenarios.load("EXTERNAL_SPEC_PHASE2.json"))

    def test_stubs_as_specified_are_confirmed(self):
        rows, summaries, audit = scenarios.run_targets(self.first, library_stub)
        self.assertEqual({name: row["verdict"] for name, row in rows.items()}, {"T1": "CONFIRMED", "T2": "CONFIRMED"})
        self.assertEqual(summaries["summary_T1_vulnerable"]["sesstrace_invariant"], {"replay_after_lifetime": "FAIL"})
        self.assertEqual(summaries["summary_T1_fixed"]["sesstrace_invariant"], {"replay_after_lifetime": "PASS"})
        self.assertEqual(summaries["summary_T2_vulnerable"]["sesstrace_invariant"],
                         {"replay_after_logout": "FAIL", "replay_after_lifetime": "FAIL"})
        self.assertEqual(summaries["summary_T2_fixed"]["sesstrace_invariant"],
                         {"replay_after_logout": "FAIL", "replay_after_lifetime": "PASS"})
        self.assertTrue(audit["clean"], audit["problems"])
        self.assertEqual(audit["runs"], 4)

    def test_repair_that_does_not_repair_is_not_confirmed(self):
        def stub(entry, variant):
            return library_stub(entry, variant, repairs=entry["id"] != "T1")
        rows, _, _ = scenarios.run_targets(self.first, stub)
        self.assertEqual(rows["T1"]["verdict"], "NOT_CONFIRMED")
        self.assertEqual(rows["T2"]["verdict"], "CONFIRMED")

    def test_failing_control_is_inconclusive(self):
        def stub(entry, variant):
            broken = 2 if (entry["id"], variant) == ("T2", "fixed") else None
            return library_stub(entry, variant, break_login_after=broken)
        rows, _, audit = scenarios.run_targets(self.first, stub)
        self.assertEqual(rows["T2"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(rows["T1"]["verdict"], "CONFIRMED")
        self.assertFalse(audit["problems"], audit["problems"])
        self.assertTrue(audit["requests_not_sent"])

    def test_checkout_at_another_commit_is_inconclusive(self):
        rows, _, _ = scenarios.run_targets(self.first, library_stub, wrong_head=("T1", "vulnerable"))
        self.assertEqual(rows["T1"]["verdict"], "INCONCLUSIVE")
        self.assertIn("vulnerable: checkout is not at the pinned commit", rows["T1"]["reasons"])

    def test_second_series_as_specified_is_confirmed(self):
        rows, summaries, audit = scenarios.run_targets(self.second, library_stub)
        self.assertEqual({name: row["verdict"] for name, row in rows.items()}, {"T3": "CONFIRMED", "T4": "CONFIRMED"})
        self.assertIs(summaries["summary_T4_fixed"]["concurrency"][0]["order_ok"], True)
        self.assertEqual(summaries["summary_T4_vulnerable"]["waits"], [])
        self.assertEqual(rows["T4"]["reasons"], [])
        self.assertTrue(audit["clean"], audit["problems"])


class ConcurrentLogout(unittest.TestCase):
    """The plan of T4: a slow request that is still running when the user logs out."""

    @classmethod
    def setUpClass(cls):
        cls.spec = scenarios.shortened(scenarios.load("EXTERNAL_SPEC_PHASE2.json"), only=["T4"])

    def test_repair_that_does_not_repair_is_not_confirmed(self):
        rows, _, _ = scenarios.run_targets(self.spec, lambda entry, variant: library_stub(entry, variant, repairs=False))
        self.assertEqual(rows["T4"]["verdict"], "NOT_CONFIRMED")

    def test_slow_request_that_ends_before_the_logout_is_inconclusive(self):
        def stub(entry, variant):
            return library_stub(entry, variant, slow=0.05) if variant == "fixed" else library_stub(entry, variant)
        rows, _, _ = scenarios.run_targets(self.spec, stub)
        self.assertEqual(rows["T4"]["verdict"], "INCONCLUSIVE")
        self.assertTrue(any("did not span" in reason for reason in rows["T4"]["reasons"]), rows["T4"]["reasons"])

    def test_logout_without_effect_is_inconclusive(self):
        def stub(entry, variant):
            return library_stub(entry, variant, logout_noop=variant == "vulnerable")
        rows, _, _ = scenarios.run_targets(self.spec, stub)
        self.assertEqual(rows["T4"]["verdict"], "INCONCLUSIVE")


class Cells(unittest.TestCase):
    """Several runs per cell: validity per run, counts, categories, the verdict rule and the class reading."""

    @classmethod
    def setUpClass(cls):
        cls.full = scenarios.load("SPEC_CELLS.json")

    def cells(self, only=None, repeats=1):
        return scenarios.shortened(self.full, only=only, repeats=repeats)

    def test_the_specification_names_the_eight_library_cells(self):
        self.assertEqual([entry["id"] for entry in self.full["targets"]],
                         ["T1.logout", "T1.lifetime", "T2.logout", "T2.lifetime",
                          "T3.logout", "T3.lifetime", "T4.logout", "T4.concurrent_logout"])

    def test_stubs_as_specified_confirm_every_cell(self):
        rows, report, audit = scenarios.run_cells(self.cells(), lambda entry, variant, run: library_stub(entry, variant))
        self.assertEqual({row["verdict"] for row in rows.values()}, {"CONFIRMED"},
                         {name: row["reasons"][:2] for name, row in rows.items()})
        for row in rows.values():
            self.assertEqual(row["observed_category"], row["expected_category"], row["cell"])
        self.assertEqual(rows["T1.lifetime"]["count_text"],
                         "vulnerable 1 of 1 accepted, 0 of 1 refused, fixed 0 of 1 accepted, 1 of 1 refused")
        self.assertEqual(report["counts"], {"CONFIRMED": 8, "NOT_CONFIRMED": 0, "INCONCLUSIVE": 0})
        reading = {row["target"]: row for row in report["reading"]}
        self.assertEqual([reading[target]["agrees_with_frozen_class"] for target in ("T1", "T2", "T3", "T4")],
                         [True, False, True, True])
        self.assertEqual(reading["T2"]["contracts_whose_outcome_changes"], ["lifetime"])
        self.assertEqual(reading["T4"]["contracts_whose_outcome_changes"], ["concurrent_logout"])
        self.assertTrue(audit["clean"], audit["problems"])
        self.assertEqual(audit["runs"], 16)

    def test_one_fixed_run_that_does_not_repair(self):
        def stub(entry, variant, run):
            return library_stub(entry, variant, repairs=run != 2)
        rows, _, _ = scenarios.run_cells(self.cells(only=["T1.lifetime"], repeats=2), stub)
        row = rows["T1.lifetime"]
        self.assertEqual(row["verdict"], "NOT_CONFIRMED")
        self.assertEqual(row["observed_category"], "MIXED")
        self.assertEqual(row["revisions"]["fixed"]["count_text"], "fixed 1 of 2 accepted, 1 of 2 refused")

    def test_one_run_with_a_failing_control(self):
        def stub(entry, variant, run):
            broken = 2 if (variant, run) == ("vulnerable", 1) else None
            return library_stub(entry, variant, break_login_after=broken)
        rows, _, _ = scenarios.run_cells(self.cells(only=["T3.logout"], repeats=2), stub)
        self.assertEqual(rows["T3.logout"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(rows["T3.logout"]["revisions"]["vulnerable"]["valid_runs"], 1)

    def test_one_run_whose_target_never_became_ready(self):
        rows, _, audit = scenarios.run_cells(self.cells(only=["T4.logout"], repeats=2),
                                             lambda entry, variant, run: library_stub(entry, variant),
                                             not_ready={("T4.logout", "fixed", 1)})
        self.assertEqual(rows["T4.logout"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(rows["T4.logout"]["revisions"]["fixed"]["valid_runs"], 1)
        self.assertEqual(audit["runs_without_records"], ["T4.logout fixed run_01"])


if __name__ == "__main__":
    unittest.main()
