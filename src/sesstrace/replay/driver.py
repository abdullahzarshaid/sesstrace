"""Drive one entry of a specification against a running target.

The target is anything that speaks the endpoint contract over HTTP:

    GET /login?user=<alice|bob>   200 {"logged_in": true} and a cookie `sid`
    GET /profile                  200 {"sub": <user>, "rp": "RP1"}  or  401 {"error": "no_session"}
    GET /logout                   200 {"logged_out": true}

A library is put behind a small host application that speaks it; a complete
application is put behind an adapter that translates it into the application's
own requests. The driver talks only to the base address it is given.

Plan steps
    login               log one user in and keep the cookie under a name
    profile             the protected operation with a kept cookie
    logout              log out with a kept cookie
    wait_since          wait until a number of seconds has passed since a login
    profile_background  send one profile request on a second thread and go on
    pause               sleep for a number of seconds
    join                wait for the background request and judge its answer
    event               one more request that fires an event (password change,
                        account disabled, grant withdrawn); it carries no cookie
    profile_unknown     profile with a value that was never issued

Every request goes through the trace recorder, so the trace is the record of
what was sent. Cookie values never reach the trace.
"""
import json
import secrets
import threading
import time
from pathlib import Path

from ..fileio import write_text
from ..outcome import OperationOutcome, operation_outcome, replay_verdict
from ..trace import Trace
from . import spec as specification

NOT_EXECUTED = OperationOutcome(None, False, False, None, "not_executed")


class ReplayRun:
    """One run of one entry at one revision."""

    def __init__(self, entry, variant, base_url):
        if variant not in specification.VARIANTS:
            raise ValueError("the revision must be 'vulnerable' or 'fixed'")
        self.entry = entry
        self.variant = variant
        self.base = base_url.rstrip("/")
        self.trace = Trace(entry["id"], variant, 0)
        self.trace.register_host(self.base, "target")
        self.credentials = {}       # name in the plan -> {"cookie", "user", "id", "t"} or None
        self.checkpoints = {}
        self.outcomes = {}
        self.waits = []
        self.pauses = []
        self.concurrency = []
        self.errors = []
        self.sent_at = {}           # checkpoint -> (time sent, time answered)
        self.background = {}        # handle -> job
        self.started = time.monotonic()

    # ------------------------------------------------------------------ helpers
    def _judge(self, response, user):
        outcome = operation_outcome(response, {"user": user, "expected_rp": "RP1"}, "profile")
        word = "success" if outcome.success else "denied" if outcome.denied else "other"
        return outcome, word

    def _note_transport_error(self, response):
        if response.error:
            self.errors.append({"step": response.request_id, "error": response.error})

    def _missing_credential(self, checkpoint, reason="no_artifact"):
        self.checkpoints[checkpoint] = {"outcome": "other", "status": None, "reason": reason, "step": None}
        self.outcomes[checkpoint] = NOT_EXECUTED

    def _relative(self, moment):
        return None if moment is None else round(moment - self.started, 3)

    # -------------------------------------------------------------------- steps
    def _login(self, step):
        response = self.trace.http("GET", self.base + "/login?user=" + step["user"], actor=step["as"])
        cookie = response.cookie("sid")
        issued = response.status == 200 and response.json().get("logged_in") is True and bool(cookie)
        self._note_transport_error(response)
        if not issued:
            self.errors.append({"step": response.request_id, "error": "login_did_not_issue_a_session"})
            self.credentials[step["artifact"]] = None
            return
        artifact_id = self.trace.register_artifact("session_cookie", step["as"], cookie, step["artifact"])
        self.credentials[step["artifact"]] = {"cookie": cookie, "user": step["user"], "id": artifact_id, "t": time.monotonic()}

    def _profile_or_logout(self, step):
        kind = step["do"]
        checkpoint = step["checkpoint"]
        credential = self.credentials.get(step["artifact"])
        if credential is None:
            self._missing_credential(checkpoint)
            return
        sent = time.monotonic()
        response = self.trace.http("GET", self.base + "/" + kind, cookies={"sid": credential["cookie"]},
                                   actor=step["as"], note=step.get("note"))
        self.sent_at[checkpoint] = (sent, time.monotonic())
        self._note_transport_error(response)
        if kind == "profile":
            outcome, word = self._judge(response, credential["user"])
            self.checkpoints[checkpoint] = {"outcome": word, "status": outcome.status, "reason": outcome.reason,
                                            "step": outcome.request_id, "artifact": credential["id"]}
            self.outcomes[checkpoint] = outcome
        else:
            reported = response.status == 200 and response.json().get("logged_out") is True
            self.checkpoints[checkpoint] = {"outcome": "reported" if reported else "other", "status": response.status,
                                            "step": response.request_id, "artifact": credential["id"]}

    def _wait_since(self, step):
        credential = self.credentials.get(step["artifact"])
        required = float(self.entry[step["seconds"]])
        if credential is None:
            self.waits.append({"required_seconds": required, "measured_seconds": None, "note": step.get("note")})
            return
        while time.monotonic() - credential["t"] < required:
            time.sleep(0.2)
        self.waits.append({"required_seconds": required, "measured_seconds": round(time.monotonic() - credential["t"], 2),
                           "since_artifact": credential["id"], "after_step": self.trace.current_step(), "note": step.get("note")})

    def _profile_background(self, step):
        credential = self.credentials.get(step["artifact"])
        job = {"credential": credential, "result": None, "t_sent": None, "t_done": None, "thread": None}
        self.background[step["handle"]] = job
        if credential is None:
            return

        def send():
            job["t_sent"] = time.monotonic()
            job["result"] = self.trace.http("GET", self.base + step.get("path", "/profile"),
                                            cookies={"sid": credential["cookie"]}, actor=step["as"], note=step.get("note"))
            job["t_done"] = time.monotonic()

        job["thread"] = threading.Thread(target=send, daemon=True)
        job["thread"].start()
        while job["t_sent"] is None:
            time.sleep(0.01)

    def _pause(self, step):
        required = float(self.entry[step["seconds"]])
        begun = time.monotonic()
        time.sleep(required)
        self.pauses.append({"required_seconds": required, "measured_seconds": round(time.monotonic() - begun, 2),
                            "after_step": self.trace.current_step(), "note": step.get("note")})

    def _join(self, step):
        checkpoint = step["checkpoint"]
        job = self.background.get(step["handle"])
        if job is None or job["thread"] is None:
            self._missing_credential(checkpoint)
            return
        job["thread"].join(timeout=float(self.entry.get("join_timeout_seconds", 30)))
        response = job["result"]
        if job["thread"].is_alive() or response is None:
            self.errors.append({"step": None, "error": "background_request_did_not_finish"})
            self._missing_credential(checkpoint, reason="not_finished")
            return
        self._note_transport_error(response)
        outcome, word = self._judge(response, job["credential"]["user"])
        self.checkpoints[checkpoint] = {"outcome": word, "status": outcome.status, "reason": outcome.reason,
                                        "step": outcome.request_id, "artifact": job["credential"]["id"]}
        self.outcomes[checkpoint] = outcome
        spanned = step.get("spans_checkpoint")
        if not spanned:
            return
        # The background request must have been sent before the spanned request and answered after it.
        span = self.sent_at.get(spanned)
        in_order = span is not None and job["t_sent"] < span[0] and span[1] < job["t_done"]
        self.concurrency.append({
            "background_checkpoint": checkpoint, "spans_checkpoint": spanned,
            "background_sent_s": self._relative(job["t_sent"]),
            "spanned_sent_s": self._relative(span[0] if span else None),
            "spanned_answered_s": self._relative(span[1] if span else None),
            "background_answered_s": self._relative(job["t_done"]),
            "order_ok": in_order,
        })
        if not in_order:
            self.errors.append({"step": response.request_id, "error": "background_request_did_not_span_" + spanned})

    def _event(self, step):
        response = self.trace.http("GET", self.base + step["path"], actor=step["as"], note=step.get("note"))
        self._note_transport_error(response)
        reported = response.status == 200 and response.json().get(step["field"]) is True
        self.checkpoints[step["checkpoint"]] = {"outcome": "reported" if reported else "other",
                                                "status": response.status, "step": response.request_id}

    def _profile_unknown(self, step):
        value = secrets.token_urlsafe(32)
        artifact_id = self.trace.register_artifact("never_issued_value", step["as"], value, "never issued")
        response = self.trace.http("GET", self.base + "/profile", cookies={"sid": value}, actor=step["as"], note=step.get("note"))
        self._note_transport_error(response)
        outcome, word = self._judge(response, step["user"])
        self.checkpoints[step["checkpoint"]] = {"outcome": word, "status": outcome.status, "reason": outcome.reason,
                                                "step": outcome.request_id, "artifact": artifact_id}
        self.outcomes[step["checkpoint"]] = outcome

    # ---------------------------------------------------------------------- run
    def run(self):
        """Send the plan and return the summary of the run."""
        handlers = {
            "login": self._login, "profile": self._profile_or_logout, "logout": self._profile_or_logout,
            "wait_since": self._wait_since, "profile_background": self._profile_background, "pause": self._pause,
            "join": self._join, "event": self._event, "profile_unknown": self._profile_unknown,
        }
        for step in self.entry["plan"]:
            self.trace.set_phase(step["phase"])
            handler = handlers.get(step["do"])
            if handler is None:
                raise ValueError("unknown plan step: %s" % step["do"])
            handler(step)
        return self.summary()

    def _invariants(self):
        first_use = self.outcomes.get("pre_alice")
        baseline = isinstance(first_use, OperationOutcome) and first_use.success
        result = {}
        for name in self.entry["replay_checkpoints"]:
            valid = bool(baseline and not self.errors)
            if name == "replay_after_logout":
                valid = valid and self.checkpoints.get("termination", {}).get("outcome") == "reported"
            for checkpoint, word in self.entry.get("replay_requires", {}).get(name, {}).items():
                valid = valid and self.checkpoints.get(checkpoint, {}).get("outcome") == word
            result[name] = replay_verdict(self.entry["id"], self.outcomes.get(name, NOT_EXECUTED), valid)
        return result

    def summary(self):
        summary = {
            "target": self.entry["id"], "cve": self.entry.get("cve"), "package": self.entry.get("package"), "variant": self.variant,
            "commit_expected": self.entry[self.variant + "_commit"], "lifetime_seconds": self.entry.get("lifetime_seconds"),
            "checkpoints": self.checkpoints, "sesstrace_invariant": self._invariants(), "waits": self.waits,
            "errors": self.errors, "http_steps": self.trace.current_step(),
            "utc_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if self.pauses:
            summary["pauses"] = self.pauses
        if self.concurrency:
            summary["concurrency"] = self.concurrency
        return summary

    def trace_document(self):
        return {"mechanism": self.entry["id"], "variant": self.variant,
                "artifacts": self.trace.artifacts, "steps": self.trace.steps}


def run_entry(spec, entry_id, variant, base_url, out_dir):
    """Run one entry and write its summary and trace. Returns the summary."""
    run = ReplayRun(specification.entry(spec, entry_id), variant, base_url)
    summary = run.run()
    out_dir = Path(out_dir)
    write_text(out_dir / ("summary_%s_%s.json" % (entry_id, variant)), json.dumps(summary, indent=2) + "\n")
    write_text(out_dir / ("trace_%s_%s.json" % (entry_id, variant)), json.dumps(run.trace_document(), indent=1) + "\n")
    return summary
