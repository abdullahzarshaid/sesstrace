"""Mechanism drivers M1..M6.

Each driver answers three questions for one mechanism, all over real HTTP:

  setup(lab, user, actor)        obtain the artifact(s) for `user`; register them
                                 in the trace; return a context dict
  operate(lab, ctx, actor)       perform THE protected operation with the
                                 pre-termination artifact; return OperationOutcome
                                 with fixture-specific semantic success/denial
                                 (HTTP 200 alone does not establish success)
  terminate(lab, ctx, actor)     fire the termination event for `ctx`'s user;
                                 return the HTTP status the event reported

Metadata (title, trigger, declared expected scope, CWE rule path, uncertainty)
is loaded from metadata/<id>.json so that the file a reader opens is the
same data the runner emits.
"""
import json
from pathlib import Path

from ..outcome import operation_outcome

METADATA_DIR = Path(__file__).resolve().parent / "metadata"


def load_metadata(directory=None):
    """Read the declared metadata of every mechanism (one JSON file each)."""
    directory = Path(directory) if directory else METADATA_DIR
    meta = {}
    for path in sorted(directory.glob("M*.json")):
        with open(path, encoding="utf-8") as f:
            meta[path.stem] = json.load(f)
    return meta


class _Base:
    id = None
    success_status = 200

    def setup(self, lab, user, actor):
        raise NotImplementedError

    def operate(self, lab, ctx, actor):
        raise NotImplementedError

    def terminate(self, lab, ctx, actor):
        raise NotImplementedError


class M1(_Base):
    """Server-side session survives application logout (RP1)."""
    id = "M1"

    def setup(self, lab, user, actor):
        idp_c = lab.idp_login(user, actor)
        lab.trace.register_artifact("idp_session_cookie", actor, idp_c)
        rp_c = lab.sso_login("RP1", idp_c, actor)
        aid = lab.trace.register_artifact("rp_session_cookie", actor, rp_c, "RP1 session")
        return {"user": user, "rp_cookie": rp_c, "artifact": aid}

    def operate(self, lab, ctx, actor):
        return operation_outcome(lab.trace.http("GET", lab.rp_url("RP1") + "/profile",
                              cookies={"rp_sid": ctx["rp_cookie"]}, actor=actor), ctx, "profile")

    def terminate(self, lab, ctx, actor):
        return lab.trace.http("GET", lab.rp_url("RP1") + "/logout?federated=0",
                              cookies={"rp_sid": ctx["rp_cookie"]}, actor=actor,
                              note="TERMINATION: application logout (local only)")


class M2(_Base):
    """Access token accepted by the RS after federated logout."""
    id = "M2"

    def setup(self, lab, user, actor):
        idp_c = lab.idp_login(user, actor)
        lab.trace.register_artifact("idp_session_cookie", actor, idp_c)
        rp_c = lab.sso_login("RP1", idp_c, actor)
        lab.trace.register_artifact("rp_session_cookie", actor, rp_c)
        tok = lab.rp_tokens("RP1", rp_c, actor)
        aid = lab.trace.register_artifact("oauth_access_token", "RP1 for " + actor, tok["access"])
        lab.trace.register_artifact("oauth_refresh_token", "RP1 for " + actor, tok["refresh"])
        lab.trace.register_artifact("oidc_id_token", "RP1 for " + actor, tok["id_token"])
        return {"user": user, "rp_cookie": rp_c, "access": tok["access"], "artifact": aid}

    def operate(self, lab, ctx, actor):
        return operation_outcome(lab.trace.http("GET", lab.rs_url + "/api/data",
                              headers={"Authorization": "Bearer " + ctx["access"]}, actor=actor), ctx, "resource")

    def terminate(self, lab, ctx, actor):
        return lab.trace.http("GET", lab.rp_url("RP1") + "/logout",
                              cookies={"rp_sid": ctx["rp_cookie"]}, actor=actor,
                              note="TERMINATION: RP logout, federated to the IdP")


class M3(_Base):
    """Refresh token still mints tokens after RFC 7009 revocation."""
    id = "M3"

    def setup(self, lab, user, actor):
        idp_c = lab.idp_login(user, actor)
        lab.trace.register_artifact("idp_session_cookie", actor, idp_c)
        rp_c = lab.sso_login("RP1", idp_c, actor)
        lab.trace.register_artifact("rp_session_cookie", actor, rp_c)
        tok = lab.rp_tokens("RP1", rp_c, actor)
        lab.trace.register_artifact("oauth_access_token", "RP1 for " + actor, tok["access"])
        aid = lab.trace.register_artifact("oauth_refresh_token", "RP1 for " + actor, tok["refresh"])
        return {"user": user, "refresh": tok["refresh"], "artifact": aid}

    def operate(self, lab, ctx, actor):
        cid, sec = lab.client("RP1")
        r = lab.trace.http("POST", lab.idp_url + "/token",
                           data={"grant_type": "refresh_token", "refresh_token": ctx["refresh"],
                                 "client_id": cid, "client_secret": sec}, actor=actor)
        outcome = operation_outcome(r, ctx, "refresh")
        if outcome.success:
            # A syntactically present token is not yet proof it conveys authority.
            token = r.json()["access_token"]
            lab.trace.register_artifact("oauth_access_token", actor, token, "refresh-derived resource witness")
            resource = lab.trace.http("GET", lab.rs_url + "/api/data",
                                      headers={"Authorization": "Bearer " + token}, actor=actor)
            witness = operation_outcome(resource, ctx, "resource")
            outcome.success = witness.success
            outcome.reason = "usable_token_issued" if witness.success else "token_usability_unproven"
            outcome.witness_request_id = resource.request_id
        return outcome

    def terminate(self, lab, ctx, actor):
        cid, sec = lab.client("RP1")
        return lab.trace.http("POST", lab.idp_url + "/revoke",
                              data={"token": ctx["refresh"], "token_type_hint": "refresh_token",
                                    "client_id": cid, "client_secret": sec}, actor=actor,
                              note="TERMINATION: RFC 7009 revocation of the refresh token")


class M4(_Base):
    """Second RP session survives federated (back-channel) logout."""
    id = "M4"

    def setup(self, lab, user, actor):
        idp_c = lab.idp_login(user, actor)
        lab.trace.register_artifact("idp_session_cookie", actor, idp_c)
        rp1_c = lab.sso_login("RP1", idp_c, actor)
        lab.trace.register_artifact("rp_session_cookie", actor + " (RP1)", rp1_c)
        rp2_c = lab.sso_login("RP2", idp_c, actor)
        aid = lab.trace.register_artifact("rp_session_cookie", actor + " (RP2)", rp2_c, "RP2 session")
        return {"user": user, "rp1_cookie": rp1_c, "rp2_cookie": rp2_c, "artifact": aid, "expected_rp": "RP2"}

    def operate(self, lab, ctx, actor):
        return operation_outcome(lab.trace.http("GET", lab.rp_url("RP2") + "/profile",
                              cookies={"rp_sid": ctx["rp2_cookie"]}, actor=actor), ctx, "profile")

    def terminate(self, lab, ctx, actor):
        return lab.trace.http("GET", lab.rp_url("RP1") + "/logout",
                              cookies={"rp_sid": ctx["rp1_cookie"]}, actor=actor,
                              note="TERMINATION: RP1 logout -> IdP logout -> back-channel to RP2")


class M5(_Base):
    """Cached authorization decision served after token revocation."""
    id = "M5"

    def setup(self, lab, user, actor):
        idp_c = lab.idp_login(user, actor)
        lab.trace.register_artifact("idp_session_cookie", actor, idp_c)
        rp_c = lab.sso_login("RP1", idp_c, actor)
        lab.trace.register_artifact("rp_session_cookie", actor, rp_c)
        tok = lab.rp_tokens("RP1", rp_c, actor)
        aid = lab.trace.register_artifact("oauth_access_token", "RP1 for " + actor, tok["access"])
        lab.trace.register_artifact("oauth_refresh_token", "RP1 for " + actor, tok["refresh"])
        return {"user": user, "access": tok["access"], "artifact": aid}

    def operate(self, lab, ctx, actor):
        return operation_outcome(lab.trace.http("GET", lab.rs_url + "/api/data",
                              headers={"Authorization": "Bearer " + ctx["access"]}, actor=actor), ctx, "resource")

    def terminate(self, lab, ctx, actor):
        cid, sec = lab.client("RP1")
        return lab.trace.http("POST", lab.idp_url + "/revoke",
                              data={"token": ctx["access"], "token_type_hint": "access_token",
                                    "client_id": cid, "client_secret": sec}, actor=actor,
                              note="TERMINATION: RFC 7009 revocation of the access token")


class M6(_Base):
    """Password change does not terminate the user's other sessions."""
    id = "M6"

    def setup(self, lab, user, actor):
        # Browser A: the session that will perform the password change.
        idp_a = lab.idp_login(user, actor + " browser A")
        lab.trace.register_artifact("idp_session_cookie", actor + " browser A", idp_a, "session performing the change")
        # Browser B: a second, independent session of the same user, with tokens.
        idp_b = lab.idp_login(user, actor + " browser B")
        lab.trace.register_artifact("idp_session_cookie", actor + " browser B", idp_b)
        rp_b = lab.sso_login("RP1", idp_b, actor + " browser B")
        lab.trace.register_artifact("rp_session_cookie", actor + " browser B", rp_b)
        tok = lab.rp_tokens("RP1", rp_b, actor + " browser B")
        aid = lab.trace.register_artifact("oauth_access_token", "RP1 for " + actor + " browser B", tok["access"],
                                          "issued under browser B's session")
        lab.trace.register_artifact("oauth_refresh_token", "RP1 for " + actor + " browser B", tok["refresh"])
        return {"user": user, "idp_a": idp_a, "access": tok["access"], "artifact": aid}

    def operate(self, lab, ctx, actor):
        return operation_outcome(lab.trace.http("GET", lab.rs_url + "/api/data",
                              headers={"Authorization": "Bearer " + ctx["access"]}, actor=actor), ctx, "resource")

    def terminate(self, lab, ctx, actor):
        user = ctx["user"]
        new_pw = lab.passwords[user] + "-rotated"
        r = lab.trace.http("POST", lab.idp_url + "/password",
                           data={"current_password": lab.passwords[user], "new_password": new_pw},
                           cookies={"idp_sid": ctx["idp_a"]}, actor=actor + " browser A",
                           note="TERMINATION: password change from browser A")
        if r.status == 200:
            lab.passwords[user] = new_pw       # the harness now logs in with the new password
        return r


MECHANISMS = [M1(), M2(), M3(), M4(), M5(), M6()]
