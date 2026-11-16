"""The endpoint contracts: when a response counts as success, as denial, or as neither."""
import unittest
from types import SimpleNamespace

from sesstrace.lab.mechanisms import MECHANISMS
from sesstrace.outcome import operation_outcome, replay_verdict
from sesstrace.trace import Response

ALICE = {"user": "alice"}
MECHANISM_IDS = ["M1", "M2", "M3", "M4", "M5", "M6"]


class ResponseContracts(unittest.TestCase):
    def test_token_status_without_valid_payload_is_inconclusive(self):
        bodies = ['{}', '[]', 'null', '<html>login</html>', '{"access_token":null}', '{"access_token":""}',
                  '{"access_token":"abc","token_type":"Other"}']
        for body in bodies:
            with self.subTest(body=body):
                outcome = operation_outcome(Response(200, [], body), ALICE, "refresh")
                self.assertEqual(replay_verdict("M3", outcome), "INCONCLUSIVE")

    def test_malformed_request_denials_not_revocation(self):
        bodies = ['{}', '{"error":"invalid_client"}', '{"error":"unsupported_grant_type"}',
                  '{"error":"invalid_request"}', '{"error":null}']
        for body in bodies:
            with self.subTest(body=body):
                outcome = operation_outcome(Response(400, [], body), ALICE, "refresh")
                self.assertEqual(replay_verdict("M3", outcome), "INCONCLUSIVE")

    def test_wrong_principal_data_and_login_bodies_are_inconclusive(self):
        cases = [("resource", '{"sub":"bob","data":"report"}'),
                 ("resource", '{"sub":"alice","data":"wrong"}'),
                 ("profile", '{"sub":"alice","rp":"RP2"}'),
                 ("profile", '{"logged_in":true}')]
        for kind, body in cases:
            with self.subTest(kind=kind, body=body):
                outcome = operation_outcome(Response(200, [], body), ALICE, kind)
                self.assertFalse(outcome.success)
                self.assertEqual(replay_verdict("M1", outcome), "INCONCLUSIVE")

    def test_missing_artifact_denial_not_proof_of_fix(self):
        outcome = operation_outcome(Response(401, [], '{"error":"missing_token"}'), ALICE, "resource")
        self.assertEqual(replay_verdict("M2", outcome), "INCONCLUSIVE")

    def test_positive_response_contract(self):
        response = Response(200, [], '{"sub":"alice","data":"report"}', request_id=5)
        outcome = operation_outcome(response, ALICE, "resource")
        self.assertEqual(replay_verdict("M2", outcome), "FAIL")
        self.assertEqual(replay_verdict("M2", outcome, scenario_valid=False), "INCONCLUSIVE")

    def test_minted_but_unusable_token_not_residual_capability(self):
        responses = iter([Response(200, [], '{"access_token":"synthetic-invalid","token_type":"Bearer"}', request_id=1),
                          Response(401, [], '{"error":"invalid_token"}', request_id=2)])
        trace = SimpleNamespace(http=lambda *args, **kwargs: next(responses),
                                register_artifact=lambda *args, **kwargs: "A1")
        lab = SimpleNamespace(trace=trace, client=lambda rp: ("a", "b"), idp_url="http://unused", rs_url="http://unused")
        outcome = MECHANISMS[2].operate(lab, {"refresh": "test", "user": "alice"}, "alice")
        self.assertEqual(outcome.reason, "token_usability_unproven")
        self.assertEqual(replay_verdict("M3", outcome), "INCONCLUSIVE")


class StatusAloneIsNeverEnough(unittest.TestCase):
    def test_unexpected_responses_not_proof_of_fix(self):
        for mechanism in MECHANISM_IDS:
            for status in (None, 201, 204, 302, 404, 500, 503):
                with self.subTest(mechanism=mechanism, status=status):
                    self.assertEqual(replay_verdict(mechanism, status), "INCONCLUSIVE")

    def test_contract_specific_denial(self):
        for mechanism in MECHANISM_IDS:
            with self.subTest(mechanism=mechanism):
                # A bare status code, even the expected one, proves nothing.
                self.assertEqual(replay_verdict(mechanism, 200), "INCONCLUSIVE")
                if mechanism == "M3":
                    kind, status, body = "refresh", 400, '{"error":"invalid_grant"}'
                elif mechanism in ("M1", "M4"):
                    kind, status, body = "profile", 401, '{"error":"no_session"}'
                else:
                    kind, status, body = "resource", 401, '{"error":"invalid_token"}'
                outcome = operation_outcome(Response(status, [], body), ALICE, kind)
                self.assertEqual(replay_verdict(mechanism, outcome), "PASS")


if __name__ == "__main__":
    unittest.main()
