"""The driver and the evaluator on the plans of complete applications, against stub servers.

These plans add two kinds of step: an event fired through one more request
(password change, account disabled, grant withdrawn) and a control that
presents a value that was never issued.
"""
import unittest

from tests import scenarios
from tests.stubs import ApplicationStub, ShareStub

# A release that revokes nothing, and one whose logout revokes the session.
RELEASE = {"vulnerable": {}, "fixed": {"logout_revokes": True}}


def application_stub(entry, variant, accept_unknown=False, **override):
    behaviour = dict(RELEASE[variant], **override)
    return ApplicationStub(lifetime=entry.get("lifetime_seconds", 3600), accept_unknown=accept_unknown, **behaviour)


class ApplicationCells(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        full = scenarios.load("SPEC_CELLS_D.json")
        cls.targets = {entry["target"] for entry in full["targets"]}
        names = [entry["id"] for entry in full["targets"] if entry["target"] == "T7"]
        cls.spec = scenarios.shortened(full, only=names, repeats=1)

    def test_the_specification_holds_the_four_applications(self):
        self.assertEqual(self.targets, {"T5", "T6", "T7", "T8"})
        self.assertEqual([entry["expected_category"] for entry in self.spec["targets"]],
                         ["FLIPS", "REFUSED_AT_BOTH", "ACCEPTED_AT_BOTH", "ACCEPTED_AT_BOTH"])

    def test_stub_as_specified_confirms_the_four_cells(self):
        rows, report, audit = scenarios.run_cells(self.spec, lambda entry, variant, run: application_stub(entry, variant))
        for row in rows.values():
            self.assertEqual(row["verdict"], "CONFIRMED", row["reasons"])
            self.assertEqual(row["observed_category"], row["expected_category"])
        self.assertEqual(report["reading"][0]["contracts_whose_outcome_changes"], ["logout"])
        self.assertIs(report["reading"][0]["agrees_with_frozen_class"], True)
        self.assertTrue(audit["clean"], audit["problems"])

    def test_fixed_release_whose_logout_does_not_revoke(self):
        def stub(entry, variant, run):
            if (entry["id"], variant) == ("T7.logout", "fixed"):
                return application_stub(entry, variant, logout_revokes=False)
            return application_stub(entry, variant)
        rows, _, _ = scenarios.run_cells(self.spec, stub)
        self.assertEqual(rows["T7.logout"]["verdict"], "NOT_CONFIRMED")

    def test_accepting_a_value_never_issued_makes_every_cell_inconclusive(self):
        rows, _, _ = scenarios.run_cells(self.spec, lambda entry, variant, run: application_stub(entry, variant, accept_unknown=True))
        self.assertEqual({row["verdict"] for row in rows.values()}, {"INCONCLUSIVE"})

    def test_disable_that_revokes_at_the_vulnerable_release(self):
        def stub(entry, variant, run):
            if (entry["id"], variant) == ("T7.account_disabled", "vulnerable"):
                return application_stub(entry, variant, disable_revokes=True)
            return application_stub(entry, variant)
        rows, _, _ = scenarios.run_cells(self.spec, stub)
        self.assertEqual(rows["T7.account_disabled"]["verdict"], "NOT_CONFIRMED")


class GrantWithdrawn(unittest.TestCase):
    """The cell whose event deletes a link share (a grant), not a session."""

    @classmethod
    def setUpClass(cls):
        cls.full = scenarios.load("SPEC_CELLS_3B.json")
        cls.spec = scenarios.shortened(cls.full, only=["T5.grant_withdrawn"], repeats=1)

    def run_cell(self, vulnerable_still_works=True, fixed_still_works=False, accept_unknown=False):
        def stub(entry, variant, run):
            works = vulnerable_still_works if variant == "vulnerable" else fixed_still_works
            return ShareStub(works, accept_unknown)
        rows, report, audit = scenarios.run_cells(self.spec, stub)
        return rows["T5.grant_withdrawn"], report, audit

    def test_the_specification_names_its_two_cells(self):
        self.assertEqual([(entry["id"], entry["expected_category"]) for entry in self.full["targets"]],
                         [("T5.grant_withdrawn", "FLIPS"), ("T7.credential_change", "ACCEPTED_AT_BOTH")])

    def test_second_attempt_keeps_the_frozen_plan_and_expectations(self):
        earlier = next(entry for entry in scenarios.load("SPEC_CELLS_D.json")["targets"] if entry["id"] == "T7.credential_change")
        later = self.full["targets"][1]
        for key in ("plan", "replay_checkpoints", "control_checkpoints", "expected", "source_basis",
                    "vulnerable_commit", "fixed_commit"):
            self.assertEqual(later[key], earlier[key], key)

    def test_stub_as_specified_is_confirmed(self):
        row, report, audit = self.run_cell()
        self.assertEqual((row["verdict"], row["observed_category"]), ("CONFIRMED", "FLIPS"), row["reasons"])
        self.assertEqual(report["reading"][0]["lifecycle_condition_of_those_contracts"], ["B"])
        self.assertIs(report["reading"][0]["agrees_with_frozen_class"], True)
        self.assertTrue(audit["clean"], audit["problems"])

    def test_fixed_release_that_still_accepts_the_deleted_share(self):
        row, _, _ = self.run_cell(fixed_still_works=True)
        self.assertEqual(row["verdict"], "NOT_CONFIRMED")

    def test_accepting_a_value_never_issued_is_inconclusive(self):
        row, _, _ = self.run_cell(accept_unknown=True)
        self.assertEqual(row["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
