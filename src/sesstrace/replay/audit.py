"""Check finished runs against their plan, using the traces.

The evaluator trusts the summary the driver wrote. The audit does not: it
reads the trace of every run, which holds one record per request as it was
sent, and checks three things.

1. Plan conformance. The requests of the trace are the HTTP steps of the plan,
   in order, on the right path and with the right credential: a login
   presents nothing and receives exactly one credential, an event presents
   nothing, the unknown-credential step presents a value that was never
   issued, and the replay presents the credential of the first use.
2. Summary against trace. Every checkpoint of the summary points at the
   request the plan names for it, with the same status and credential.
3. Outcome from the trace. The outcome word of every checkpoint is derived
   again from the recorded status and answer and compared with the summary.

When a login issues no credential, the driver sends none of the later
requests that would have used it. The audit follows the same rule and lists
those requests as not sent; the evaluator counts such a run as not valid.

A run with no problem is one whose verdict rests on requests that were really
sent as planned.
"""
from pathlib import Path

from ..fileio import read_json
from .spec import VARIANTS, http_steps

# Answer fields the trace keeps as booleans; an event that reports through
# another field cannot be derived again from the trace.
RECORDED_FLAGS = ("active", "logged_out", "logged_in", "terminated", "ignored", "ok", "changed")
USES_CREDENTIAL = ("profile", "logout", "profile_background")


def _path_of(step):
    kind = step["do"]
    if kind in ("login", "logout"):
        return "/" + kind
    if kind == "profile_unknown":
        return "/profile"
    return step.get("path", "/profile").split("?")[0]


def _profile_word(record, user):
    answer = record.get("response") or {}
    if record["status"] == 200 and answer.get("sub") == user and answer.get("rp") == "RP1":
        return "success"
    if record["status"] == 401 and answer.get("error") == "no_session":
        return "denied"
    return "other"


def _flag_word(record, field):
    if field not in RECORDED_FLAGS:
        return None
    answer = record.get("response") or {}
    return "reported" if record["status"] == 200 and answer.get(field) is True else "other"


def audit_run(entry, summary, trace):
    """Check one run. Returns (problems, requests not sent); no problem means the run followed its plan."""
    records = trace["steps"]
    problems = []
    not_sent = []
    # A credential is registered when the login that issued it has been answered, so it carries
    # the number of that request. A never-issued value is registered before its own request and
    # carries the number of the request before it; it must not be taken for a login credential.
    issued_at = {}
    for artifact in trace["artifacts"]:
        if artifact["type"] != "never_issued_value":
            issued_at.setdefault(artifact["issued_at_step"], []).append(artifact)
    kinds = {artifact["id"]: artifact["type"] for artifact in trace["artifacts"]}
    credential = {}     # name in the plan -> artifact id in the trace, None when the login issued nothing
    user_of = {}        # name in the plan -> user
    derived = {}        # checkpoint -> (request number, outcome word or None, credential id)
    number = 0
    for step in http_steps(entry["plan"]):
        kind = step["do"]
        if kind in USES_CREDENTIAL and credential.get(step["artifact"]) is None:
            not_sent.append("%s with %s" % (kind, step["artifact"]))
            continue
        number += 1
        if number > len(records):
            problems.append("the trace ends after %d requests, the plan goes on with %s" % (len(records), kind))
            break
        record = records[number - 1]
        presented = record["artifact_presented"]
        if record["path"].split("?")[0] != _path_of(step):
            problems.append("request %d went to %s, the plan says %s" % (number, record["path"].split("?")[0], _path_of(step)))
        if kind == "login":
            issued = issued_at.get(number, [])
            if presented is not None:
                problems.append("request %d: a login presented a credential" % number)
            if len(issued) > 1:
                problems.append("request %d: the login registered %d credentials" % (number, len(issued)))
            credential[step["artifact"]] = issued[0]["id"] if len(issued) == 1 else None
            user_of[step["artifact"]] = step["user"]
        elif kind in USES_CREDENTIAL:
            if presented != credential[step["artifact"]]:
                problems.append("request %d presents %s, the plan says %s" % (number, presented, step["artifact"]))
            if kind == "logout":
                derived[step["checkpoint"]] = (number, _flag_word(record, "logged_out"), presented)
            elif kind == "profile":
                derived[step["checkpoint"]] = (number, _profile_word(record, user_of[step["artifact"]]), presented)
            else:
                derived["background:" + step["handle"]] = (number, _profile_word(record, user_of[step["artifact"]]), presented)
        elif kind == "event":
            if presented is not None:
                problems.append("request %d: an event presented a credential" % number)
            derived[step["checkpoint"]] = (number, _flag_word(record, step["field"]), None)
        elif kind == "profile_unknown":
            if kinds.get(presented) != "never_issued_value" or presented in credential.values():
                problems.append("request %d: the unknown-credential step presented an issued credential" % number)
            derived[step["checkpoint"]] = (number, _profile_word(record, step["user"]), presented)
    else:
        if number != len(records):
            problems.append("the trace has %d requests, the plan accounts for %d" % (len(records), number))
    for step in entry["plan"]:
        if step["do"] == "join" and "background:" + step["handle"] in derived:
            derived[step["checkpoint"]] = derived.pop("background:" + step["handle"])

    checkpoints = summary.get("checkpoints", {})
    for name, (at, word, presented) in derived.items():
        recorded = checkpoints.get(name)
        if recorded is None:
            problems.append("checkpoint %s is missing from the summary" % name)
            continue
        if recorded.get("step") != at:
            problems.append("checkpoint %s points at request %s, the plan puts it at %d" % (name, recorded.get("step"), at))
            continue
        if recorded.get("status") != records[at - 1]["status"]:
            problems.append("checkpoint %s: status %s in the summary, %s in the trace"
                            % (name, recorded.get("status"), records[at - 1]["status"]))
        if "artifact" in recorded and recorded["artifact"] != presented:
            problems.append("checkpoint %s: credential %s in the summary, %s in the trace" % (name, recorded["artifact"], presented))
        if word is not None and recorded.get("outcome") != word:
            problems.append("checkpoint %s: outcome %s in the summary, %s from the trace" % (name, recorded.get("outcome"), word))
    if summary.get("http_steps") != len(records):
        problems.append("the summary counts %s requests, the trace has %d" % (summary.get("http_steps"), len(records)))

    first_use = derived.get("pre_alice")
    for name in entry["replay_checkpoints"]:
        replay = derived.get(name)
        if replay is None or first_use is None:
            if not not_sent:
                problems.append("the replay %s or the first use is not a request of the trace" % name)
        elif replay[2] != first_use[2]:
            problems.append("the replay %s does not present the credential of the first use" % name)
        elif not first_use[0] < replay[0]:
            problems.append("the replay %s is not after the first use" % name)
    return problems, not_sent


def run_folders(spec, results_dir):
    """Yield (entry, revision, run label, folder) for every run the layout of the specification calls for."""
    results_dir = Path(results_dir)
    repeats = spec.get("repeats_per_revision")
    for entry in spec["targets"]:
        for variant in VARIANTS:
            if repeats is None:
                yield entry, variant, "single run", results_dir
            else:
                for number in range(1, int(repeats) + 1):
                    label = "run_%02d" % number
                    yield entry, variant, label, results_dir / entry["id"] / variant / label


def audit_runs(runs):
    """Audit the runs given as (entry, revision, run label, folder).

    Returns the number of runs and requests read, the runs that left no summary or no trace, the problems found
    and the requests not sent. The report is clean when every run left its records and none has a problem.
    """
    report = {"runs": 0, "http_steps": 0, "runs_without_records": [], "requests_not_sent": [], "problems": []}
    for entry, variant, label, folder in runs:
        summary_path = folder / ("summary_%s_%s.json" % (entry["id"], variant))
        trace_path = folder / ("trace_%s_%s.json" % (entry["id"], variant))
        where = "%s %s %s" % (entry["id"], variant, label)
        if not summary_path.is_file() or not trace_path.is_file():
            report["runs_without_records"].append(where)
            continue
        trace = read_json(trace_path)
        problems, not_sent = audit_run(entry, read_json(summary_path), trace)
        report["runs"] += 1
        report["http_steps"] += len(trace["steps"])
        report["problems"] += ["%s: %s" % (where, problem) for problem in problems]
        report["requests_not_sent"] += ["%s: %s" % (where, request) for request in not_sent]
    report["clean"] = not report["problems"] and not report["runs_without_records"]
    return report


def audit_results(spec, results_dir):
    """Audit every run the specification calls for in a results folder."""
    return audit_runs(run_folders(spec, results_dir))
