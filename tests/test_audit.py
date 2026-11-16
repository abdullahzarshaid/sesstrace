"""The audit must notice a run that did not follow its plan, or a summary that does not match its trace.

Each test takes the records of one real run, changes one thing and expects
the audit to name it.
"""
import copy
import unittest
from pathlib import Path

from sesstrace.fileio import read_json
from sesstrace.replay import audit, spec as specification

CHECKS = Path(__file__).resolve().parents[1] / "checks"
RUN = CHECKS / "records" / "application_cells" / "results" / "T6.account_disabled" / "fixed" / "run_01"


class TamperedRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = specification.load(CHECKS / "phase3" / "SPEC_CELLS_D.json")
        cls.entry = specification.entry(spec, "T6.account_disabled")
        cls.summary = read_json(RUN / "summary_T6.account_disabled_fixed.json")
        cls.trace = read_json(RUN / "trace_T6.account_disabled_fixed.json")

    def audit(self, change_summary=None, change_trace=None):
        summary, trace = copy.deepcopy(self.summary), copy.deepcopy(self.trace)
        if change_summary:
            change_summary(summary)
        if change_trace:
            change_trace(trace)
        problems, _ = audit.audit_run(self.entry, summary, trace)
        return problems

    def assert_found(self, problems, text):
        self.assertTrue(any(text in problem for problem in problems), problems)

    def test_untouched_run_has_no_problem(self):
        self.assertEqual(self.audit(), [])

    def test_summary_that_claims_another_outcome(self):
        def change(summary):
            summary["checkpoints"]["replay_after_account_disabled"]["outcome"] = "success"
        self.assert_found(self.audit(change_summary=change), "outcome success in the summary, denied from the trace")

    def test_summary_that_claims_another_status(self):
        def change(summary):
            summary["checkpoints"]["replay_after_account_disabled"]["status"] = 200
        self.assert_found(self.audit(change_summary=change), "status 200 in the summary, 401 in the trace")

    def test_replay_with_another_credential(self):
        def change(trace):
            trace["steps"][5]["artifact_presented"] = "A2"
        problems = self.audit(change_trace=change)
        self.assert_found(problems, "request 6 presents A2")
        self.assert_found(problems, "does not present the credential of the first use")

    def test_request_removed_from_the_trace(self):
        self.assert_found(self.audit(change_trace=lambda trace: trace["steps"].pop()), "the trace ends after 9 requests")

    def test_request_to_another_path(self):
        def change(trace):
            trace["steps"][4]["path"] = "/enable_user?field=<redacted>"
        self.assert_found(self.audit(change_trace=change), "request 5 went to /enable_user")

    def test_event_that_carries_a_credential(self):
        def change(trace):
            trace["steps"][4]["artifact_presented"] = "A1"
        self.assert_found(self.audit(change_trace=change), "an event presented a credential")

    def test_unknown_credential_step_with_an_issued_credential(self):
        def change(trace):
            trace["steps"][9]["artifact_presented"] = "A1"
        self.assert_found(self.audit(change_trace=change), "the unknown-credential step presented an issued credential")

    def test_checkpoint_that_points_at_another_request(self):
        def change(summary):
            summary["checkpoints"]["pre_alice"]["step"] = 4
        self.assert_found(self.audit(change_summary=change), "checkpoint pre_alice points at request 4")


if __name__ == "__main__":
    unittest.main()
