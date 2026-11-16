"""A scenario whose preconditions fail must never be classified."""
import json
import unittest
from dataclasses import replace

from sesstrace.lab.mechanisms import MECHANISMS, load_metadata
from sesstrace.lab.runner import run_scenario
from sesstrace.trace import Response

META = load_metadata()
BASE = MECHANISMS[0]


class FaultyMechanism:
    """M1 with one fault injected at a chosen point of the lifecycle."""

    id = BASE.id

    def __init__(self, where):
        self.where = where

    def setup(self, lab, user, actor):
        if self.where == "setup":
            raise ValueError("SYNTHETIC-SECRET-DO-NOT-LOG")
        return BASE.setup(lab, user, actor)

    def operate(self, lab, ctx, actor):
        outcome = BASE.operate(lab, ctx, actor)
        if self.where == "baseline" and lab.trace.phase == "pre_termination" and actor == "alice":
            return replace(outcome, success=False, denied=False, reason="unrecognized_response")
        if self.where == "replay" and actor.startswith("attacker"):
            return replace(outcome, status=500, success=False, denied=False, reason="unrecognized_response")
        return outcome

    def terminate(self, lab, ctx, actor):
        response = BASE.terminate(lab, ctx, actor)
        if self.where == "termination":
            return Response(200, [], "{}", request_id=response.request_id)
        return response


class ScenarioValidity(unittest.TestCase):
    def assert_invalid(self, summary, trace):
        self.assertFalse(summary["scenario_valid"])
        self.assertFalse(summary["pov_confirmed"])
        self.assertEqual(summary["invariant"], "INCONCLUSIVE")
        self.assertIsNone(summary["residual_capability"])
        self.assertEqual(trace["cwe_rule_path"]["classification"], "insufficient evidence")

    def test_failed_baseline_never_classified(self):
        self.assert_invalid(*run_scenario(FaultyMechanism("baseline"), "vulnerable", META["M1"]))

    def test_failed_termination_never_classified(self):
        self.assert_invalid(*run_scenario(FaultyMechanism("termination"), "vulnerable", META["M1"]))

    def test_failed_setup_structured_and_no_exception_secret(self):
        summary, trace = run_scenario(FaultyMechanism("setup"), "vulnerable", META["M1"])
        self.assert_invalid(summary, trace)
        self.assertNotIn("SYNTHETIC-SECRET", json.dumps([summary, trace]))
        self.assertEqual(summary["execution_error"], "ValueError")

    def test_fault_injected_server_error(self):
        summary, trace = run_scenario(FaultyMechanism("replay"), "fixed", META["M1"])
        self.assertEqual(summary["invariant"], "INCONCLUSIVE")
        self.assertFalse(summary["pof_confirmed"])
        self.assertIsNone(trace["replay"]["residual_capability"])
        self.assertEqual(trace["cwe_rule_path"]["classification"], "insufficient evidence")


if __name__ == "__main__":
    unittest.main()
