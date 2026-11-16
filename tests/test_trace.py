"""The trace recorder: nothing secret is written, and the steps point at real requests."""
import json
import socket
import unittest
from unittest.mock import patch
from urllib.error import URLError

from sesstrace.lab.mechanisms import MECHANISMS, load_metadata
from sesstrace.lab.runner import run_scenario
from sesstrace.trace import Trace

META = load_metadata()


class SafeTrace(unittest.TestCase):
    def test_free_text_nested_and_unknown_key_canaries_redacted(self):
        trace = Trace("M1", "fixed", 1)
        for canary in ("abc", "SYNTHETIC-SECRET-123456"):
            body = json.dumps({"data": {"secret": canary}, "error_description": canary,
                               canary: canary, "sub": canary, "ok": canary})
            self.assertNotIn(canary, json.dumps(trace._summarise_body(body)))
            self.assertNotIn(canary, json.dumps(trace._summarise_body(canary)))
            self.assertNotIn(canary, trace._redact_query("unknown=" + canary))
            trace.register_artifact("cookie", "alice", canary)
            self.assertNotIn(canary, json.dumps(trace.artifacts))

    def test_safe_literals_survive(self):
        trace = Trace("M1", "fixed", 1)
        summary = trace._summarise_body('{"sub":"alice","data":"report","active":true}')
        self.assertEqual(summary["data"], "report")

    def test_transport_failure_structured_without_exception_text(self):
        trace = Trace("M1", "fixed", 1)
        with patch("sesstrace.trace._OPENER.open", side_effect=URLError("SYNTHETIC-SECRET")):
            response = trace.http("GET", "http://127.0.0.1:1/profile")
        self.assertIsNone(response.status)
        self.assertEqual(response.error, "URLError")
        self.assertNotIn("SYNTHETIC-SECRET", json.dumps(trace.steps))

    def test_actual_local_connection_failure(self):
        # The port is reserved but nothing listens on it, so no other service is probed.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            trace = Trace("M1", "fixed", 1)
            response = trace.http("GET", "http://127.0.0.1:%s/profile" % reserved.getsockname()[1])
            self.assertIsNone(response.status)
            self.assertIsNotNone(response.error)


class TraceCorrelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = []
        for mechanism in MECHANISMS:
            for variant in ("vulnerable", "fixed"):
                summary, trace = run_scenario(mechanism, variant, META[mechanism.id])
                cls.runs.append((mechanism.id, variant, summary, trace))

    def test_operation_pointers_are_actual_requests(self):
        for mechanism, variant, summary, trace in self.runs:
            with self.subTest(mechanism=mechanism, variant=variant):
                replay = trace["steps"][trace["replay"]["step"] - 1]
                if mechanism == "M3":
                    expected = "/token"
                elif mechanism in ("M1", "M4"):
                    expected = "/profile"
                else:
                    expected = "/api/data"
                self.assertEqual(replay["path"], expected)
                self.assertEqual(replay["status"], summary["replay_status"])
                self.assertIsNone(replay["parent_step"])
                self.assertGreaterEqual(trace["replay"]["completion_step"], trace["replay"]["step"])
                termination = trace["steps"][trace["termination"]["step"] - 1]
                if mechanism in ("M3", "M5"):
                    prefix = "/revoke"
                elif mechanism == "M6":
                    prefix = "/password"
                else:
                    prefix = "/logout"
                self.assertTrue(termination["path"].startswith(prefix))
                self.assertIsNone(termination["parent_step"])

    def test_nested_requests_have_causal_parent(self):
        for mechanism, variant, summary, trace in self.runs:
            for step in trace["steps"]:
                if step["path"] in ("/introspect", "/backchannel_logout"):
                    self.assertIsInstance(step["parent_step"], int)
                    self.assertLess(step["parent_step"], step["step"])

    def test_refresh_success_has_resource_witness(self):
        for mechanism, variant, summary, trace in self.runs:
            if mechanism == "M3" and variant == "vulnerable":
                witness = trace["steps"][trace["replay"]["witness_request_id"] - 1]
                self.assertEqual(witness["path"], "/api/data")
                self.assertEqual(witness["response"]["sub"], "alice")
                self.assertEqual(witness["status"], 200)

    def test_nominal_patterns_and_renamed_metrics(self):
        for mechanism, variant, summary, trace in self.runs:
            self.assertEqual(summary["invariant"], "FAIL" if variant == "vulnerable" else "PASS")
            self.assertEqual(summary["negative_control_failures"], 0)
            self.assertNotIn("false_positives", summary)
            self.assertEqual(trace["schema"], "sesstrace-trace/2.0")


if __name__ == "__main__":
    unittest.main()
