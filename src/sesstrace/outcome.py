"""Typed outcome of a protected operation and the replay verdict derived from it.

Both the synthetic laboratory and the replay engine judge a response through
this module, so that "the replay succeeded" means the same thing everywhere:
the endpoint contract was met, not merely that the status code was 200.
"""
from dataclasses import dataclass


@dataclass
class OperationOutcome:
    status: object
    success: bool
    denied: bool
    request_id: object
    reason: str
    witness_request_id: object = None


def operation_outcome(response, ctx, kind):
    """Evaluate the synthetic endpoint contract, not HTTP status alone."""
    obj = response.json()
    obj = obj if isinstance(obj, dict) else {}
    if kind == "refresh":
        success = (response.status == 200 and isinstance(obj.get("access_token"), str)
                   and bool(obj["access_token"].strip()) and obj.get("token_type") == "Bearer")
        denied = response.status == 400 and obj.get("error") == "invalid_grant"
    else:
        success = response.status == 200 and obj.get("sub") == ctx["user"]
        if kind == "profile":
            success = success and obj.get("rp") == ctx.get("expected_rp", "RP1")
            denied = response.status == 401 and obj.get("error") == "no_session"
        else:
            success = success and obj.get("data") == "report"
            denied = response.status == 401 and obj.get("error") == "invalid_token"
    reason = "semantic_success" if success else "contract_denial" if denied else "unrecognized_response"
    return OperationOutcome(response.status, success, denied, response.request_id, reason)


def replay_verdict(mechanism_id, outcome, scenario_valid=True):
    """A typed semantic outcome and a valid baseline are required for any conclusion.

    FAIL          the replay completed the protected operation
    PASS          the replay met the endpoint's denial contract
    INCONCLUSIVE  anything else, or a scenario whose preconditions did not hold
    """
    if not scenario_valid or not isinstance(outcome, OperationOutcome):
        return "INCONCLUSIVE"
    if outcome.success:
        return "FAIL"
    if outcome.denied:
        return "PASS"
    return "INCONCLUSIVE"
