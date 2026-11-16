"""Expiration witnesses M7 (idle lifetime) and M8 (absolute lifetime).

Each scenario starts one small HTTP server on the loopback interface and
drives it through a fixed sequence. Time is a counter that the scenario
advances by hand, so the lifetime boundary is hit exactly and nothing sleeps.
These are policy fixtures for the laboratory, not reproductions of any CVE.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from ..fileio import write_text

LIFETIME_S = 10
MODES = ("idle", "absolute")
VARIANTS = ("vulnerable", "fixed")
PROVENANCE = "Added during artifact revision; not part of the original six-withdrawal-witness result."


class Fixture:
    """Token store with a manual clock. `fixed` switches lifetime enforcement on."""

    def __init__(self, mode, fixed, lifetime=LIFETIME_S):
        if mode not in MODES:
            raise ValueError("Unknown expiration mode")
        self.mode = mode
        self.fixed = fixed
        self.lifetime = lifetime
        self.now = 0
        self.tokens = {}
        self.serial = 0

    def login(self, user):
        self.serial += 1
        token = "synthetic-%s-%d" % (user, self.serial)
        self.tokens[token] = {"user": user, "issued": self.now, "last": self.now}
        return token

    def access(self, token):
        row = self.tokens.get(token)
        if row is None:
            return 401, {"error": "missing_artifact"}
        # An absolute lifetime counts from issue; an idle lifetime from the last use.
        base = row["issued"] if self.mode == "absolute" else row["last"]
        if self.fixed and self.now >= base + self.lifetime:
            return 401, {"error": self.mode + "_expired"}
        row["last"] = self.now
        return 200, {"resource": "profile", "principal": row["user"]}


def _handler_for(fixture):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == "/login":
                user = parse_qs(url.query).get("user", [""])[0]
                if user in ("alice", "bob"):
                    status, body = 200, {"token": fixture.login(user)}
                else:
                    status, body = 400, {"error": "invalid_user"}
            elif url.path == "/protected":
                header = self.headers.get("Authorization", "")
                token = header[len("Bearer "):] if header.startswith("Bearer ") else header
                status, body = fixture.access(token)
            else:
                status, body = 404, {"error": "unknown_path"}
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def scenario(mode, variant):
    """Run one mode in one variant and return its result row."""
    fixed = variant == "fixed"
    fixture = Fixture(mode, fixed)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(fixture))
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    steps = []

    def call(path, token=None, alias=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        request = Request("http://127.0.0.1:%d%s" % (server.server_port, path), headers=headers)
        try:
            with urlopen(request, timeout=3) as response:
                status, body = response.status, json.load(response)
        except HTTPError as error:
            status, body = error.code, json.load(error)
        # The record never holds a bearer token, a port or a wall-clock time.
        steps.append({
            "step": len(steps) + 1,
            "clock_s": fixture.now,
            "endpoint": urlsplit(path).path,
            "artifact_alias": alias,
            "status": status,
            "outcome": body.get("error") or ("token_issued" if "token" in body else "protected_operation"),
            "principal": body.get("principal"),
        })
        return status, body

    alice_ok = (200, {"resource": "profile", "principal": "alice"})
    bob_ok = (200, {"resource": "profile", "principal": "bob"})
    try:
        _, body = call("/login?user=alice", alias="alice_initial")
        old = body["token"]
        pre = call("/protected", old, "alice_initial")
        fixture.now = 9
        before = call("/protected", old, "alice_initial")
        # The use at t=9 renews an idle lifetime to t=19; an absolute one still ends at t=10.
        boundary = 19 if mode == "idle" else 10
        fixture.now = boundary - 1
        _, body = call("/login?user=bob", alias="bob_unrelated")
        bob = body["token"]
        call("/protected", bob, "bob_unrelated")
        fixture.now = boundary
        replay = call("/protected", old, "alice_initial")
        _, body = call("/login?user=alice", alias="alice_fresh")
        fresh = call("/protected", body["token"], "alice_fresh")
        unrelated = call("/protected", bob, "bob_unrelated")

        baseline = pre == alice_ok and before == alice_ok
        denied = replay == (401, {"error": mode + "_expired"})
        succeeded = replay == alice_ok
        controls = {
            "pre_condition_access": baseline,
            "fresh_login_access": fresh == alice_ok,
            "unrelated_user_access": unrelated == bob_ok,
        }
        return {
            "id": "M7" if mode == "idle" else "M8",
            "paper_class": "T",
            "mode": mode,
            "variant": variant,
            "normative_basis": "synthetic_lab_policy",
            "clock": "manually_advanced_seconds",
            "lifetime_s": LIFETIME_S,
            "boundary_s": boundary,
            "expected": "deny_at_boundary" if fixed else "residual_access_at_boundary",
            "replay_status": replay[0],
            "scenario_valid": baseline,
            "contract_satisfied": baseline and (denied if fixed else succeeded) and all(controls.values()),
            "controls": controls,
            "n_http_steps": len(steps),
            "steps": steps,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run():
    """Run both modes in both variants. Returns the results object."""
    rows = [scenario(mode, variant) for mode in MODES for variant in VARIANTS]
    return {
        "schema": "sesstrace-expiration/1.0",
        "provenance": PROVENANCE,
        "scenarios": rows,
        "summary": {
            "n_mechanisms": 2,
            "n_scenarios": len(rows),
            "n_http_steps": sum(row["n_http_steps"] for row in rows),
            "controls_passed": sum(sum(row["controls"].values()) for row in rows),
            "controls_total": sum(len(row["controls"]) for row in rows),
            "all_clean": all(row["contract_satisfied"] for row in rows),
        },
    }


def write_results(result, out_dir):
    return write_text(Path(out_dir) / "expiry_results.json", json.dumps(result, sort_keys=True, indent=2) + "\n")
