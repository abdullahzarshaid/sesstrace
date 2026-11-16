"""SessTrace runner: executes every mechanism in both variants and writes the
canonical results, the matrix, the per-scenario lifecycle traces and the
artifact inventory.

Scenario = (mechanism, variant). Each scenario gets a fresh deployment (IdP,
RP1, RP2, RS) and follows one lifecycle:

  setup             alice obtains the artifact under test; bob (unrelated user)
                    obtains the same kind of artifact
  pre_termination   negative (a): alice's legitimate artifact works (expect 200)
                    baseline: bob's artifact works (expect 200)
  termination       the mechanism's termination event, fired by/for alice;
                    it must REPORT success (200) or the scenario is invalid
  replay            the pre-termination artifact is presented again ->
                    INVARIANT: no protected operation succeeds after termination.
                    Release v2 PASS requires the mechanism's explicit denial;
                    unexpected statuses are INCONCLUSIVE, not proof of fix.
  negative_c        bob's artifact still works after alice's termination (200)
  negative_b        alice logs in afresh and the new artifact works (200)

PoV test  : on the VULNERABLE variant the scoped operation semantically succeeds
PoF test  : on the FIXED variant the invariant PASSES (contract-specific denial)
Negative-control failure: a control whose legitimate operation did not semantically succeed.
"""
import csv
import json
import os
import platform
import time

from .. import __version__
from ..outcome import OperationOutcome, replay_verdict
from ..trace import Trace
from .mechanisms import MECHANISMS, load_metadata
from .servers import Flags, Lab

INVARIANT = ("no protected operation succeeds with a pre-termination artifact "
             "after a termination event that reported success")
VARIANTS = ("vulnerable", "fixed")


def seed_for(mechanism_id, variant):
    return int(mechanism_id[1:]) * 100 + (1 if variant == "vulnerable" else 2)


def run_scenario(mech, variant, meta):
    """Run one (mechanism, variant) lifecycle. Returns (summary dict, trace dict)."""
    seed = seed_for(mech.id, variant)
    tr = Trace(mech.id, variant, seed)
    flags = Flags(vulnerable={mech.id} if variant == "vulnerable" else set())
    lab = Lab(flags, tr, seed=seed)
    unknown = OperationOutcome(None, False, False, None, "not_executed")
    pre_a = pre_b = replay = post_b = fresh_a = unknown
    term = None
    ctx_a = {"artifact": None}
    execution_error = None
    term_step = replay_step = term_complete = replay_complete = None
    try:
        tr.set_phase("setup")
        ctx_a = mech.setup(lab, "alice", "alice")
        ctx_b = mech.setup(lab, "bob", "bob")

        tr.set_phase("pre_termination")
        pre_a = mech.operate(lab, ctx_a, "alice")
        pre_b = mech.operate(lab, ctx_b, "bob")

        tr.set_phase("termination")
        term = mech.terminate(lab, ctx_a, "alice")
        term_step = term.request_id
        term_complete = tr.current_step()

        tr.set_phase("replay")
        replay = mech.operate(lab, ctx_a, "attacker (replaying %s)" % ctx_a["artifact"])
        replay_step = replay.request_id
        replay_complete = tr.current_step()

        tr.set_phase("negative_c")
        post_b = mech.operate(lab, ctx_b, "bob")

        tr.set_phase("negative_b")
        ctx_a2 = mech.setup(lab, "alice", "alice (fresh login)")
        fresh_a = mech.operate(lab, ctx_a2, "alice (fresh login)")
    except (KeyError, TypeError, ValueError, AttributeError, OSError) as exc:
        execution_error = type(exc).__name__
    finally:
        lab.close()

    term_status = term.status if term is not None else None
    term_body = term.json() if term is not None else {}
    term_body = term_body if isinstance(term_body, dict) else None
    termination_reported_success = term_status == 200 and term_body is not None
    if mech.id in {"M1", "M2", "M4"}:
        termination_reported_success = termination_reported_success and term_body.get("logged_out") is True
    elif mech.id == "M6":
        termination_reported_success = termination_reported_success and term_body.get("changed") is True
    scenario_valid = bool(termination_reported_success and isinstance(pre_a, OperationOutcome)
                          and pre_a.success and not execution_error)
    # Integer-only/ad-hoc driver outcomes cannot bypass the semantic contract.
    def safe(outcome):
        return outcome if isinstance(outcome, OperationOutcome) else unknown
    pre_a, pre_b, replay, post_b, fresh_a = map(safe, (pre_a, pre_b, replay, post_b, fresh_a))
    invariant_result = replay_verdict(mech.id, replay, scenario_valid)
    invariant_pass = invariant_result == "PASS"
    negatives = {
        "a_pre_termination_legit_works": {"expected": 200, "observed": pre_a.status, "pass": pre_a.success,
                                          "definition": "before termination the legitimate artifact works"},
        "b_fresh_login_after_termination": {"expected": 200, "observed": fresh_a.status, "pass": fresh_a.success,
                                            "definition": "after termination a fresh login of the same user works"},
        "c_unrelated_user_unaffected": {"expected": 200, "observed": post_b.status, "pass": post_b.success and pre_b.success,
                                        "definition": "an unrelated user's artifact works before and after another user's termination"},
    }
    negative_control_failures = sum(1 for n in negatives.values() if not n["pass"])

    summary = {
        "mechanism": mech.id, "variant": variant, "seed": seed,
        "pre_termination_status": pre_a.status,
        "termination_status": term_status,
        "termination_reported_success": termination_reported_success,
        "replay_status": replay.status,
        "residual_capability": None if invariant_result == "INCONCLUSIVE" else replay.success,
        "invariant": invariant_result,
        "scenario_valid": scenario_valid,
        "execution_error": execution_error,
        "replay_semantic_reason": replay.reason,
        "negatives": negatives,
        "negative_control_failures": negative_control_failures,
        "n_http_steps": len(tr.steps),
    }
    if variant == "vulnerable":
        summary["pov_expected"] = "invariant FAIL"
        summary["pov_confirmed"] = invariant_result == "FAIL" and summary["scenario_valid"]
    else:
        summary["pof_expected"] = "invariant PASS"
        summary["pof_confirmed"] = invariant_pass and summary["scenario_valid"]

    # ---- rule path: derived from what the trace shows, then labelled ----------
    rule = _rule_path(meta, scenario_valid,
                      None if invariant_result == "INCONCLUSIVE" else replay.success)
    trace = {
        "schema": "sesstrace-trace/2.0",
        "mechanism": {"id": mech.id, "title": meta["title"], "component": meta["component"],
                      "flag_location": meta["flag_location"]},
        "variant": variant,
        "seed": seed,
        "invariant_statement": INVARIANT,
        "artifact_inventory": tr.artifacts,
        "artifact_under_test": ctx_a["artifact"],
        "termination": {
            "trigger": meta.get("lifecycle_event", meta["termination_trigger"]),
            "normative_basis": meta.get("normative_basis"),
            "step": term_step, "actor": "alice", "reported_status": term_status,
            "completion_step": term_complete,
            "reported_success": termination_reported_success,
            "declared_expected_scope": meta["declared_expected_scope"],
        },
        "steps": tr.steps,
        "replay": {"step": replay_step, "artifact": ctx_a["artifact"],
                   "completion_step": replay_complete,
                   "operation": meta["protected_operation"], "status": replay.status,
                   "semantic_reason": replay.reason,
                   "witness_request_id": replay.witness_request_id,
                   "residual_capability": None if invariant_result == "INCONCLUSIVE" else replay.success},
        "invariant": {"result": invariant_result,
                      "scenario_valid": scenario_valid, "execution_error": execution_error,
                      "pre_termination_status": pre_a.status, "post_termination_status": replay.status},
        "negative_checks": negatives,
        "negative_control_failures": negative_control_failures,
        "cwe_rule_path": rule,
        "uncertainty": meta["uncertainty"],
    }
    return summary, trace


def _rule_path(meta, trigger_present, residual):
    """Explanatory lifecycle rule path, evaluated on the observed trace."""
    decision = []
    family = meta.get("lifecycle_family", "explicit_termination")
    paper_class = meta.get("paper_class", "A")
    family_label = "adjacent-authority withdrawal" if family == "adjacent_withdrawal" else "explicit termination"
    if not trigger_present:
        decision.append("baseline/setup/lifecycle-event precondition failed -> scenario invalid; no classification")
        label = "insufficient evidence"
    elif residual is None:
        decision.append("unexpected replay outcome -> inconclusive; no proof of fix or vulnerability")
        label = "insufficient evidence"
    elif residual:
        decision.append(f"lifecycle event present -> {family_label} branch (paper class {paper_class})")
        decision.append("pre-event artifact still yields the protected operation -> lifecycle failure under declared scope")
        label = f"{family_label} failure (paper class {paper_class}; explanatory metadata)"
    else:
        decision.append(f"lifecycle event present -> {family_label} branch (paper class {paper_class})")
        decision.append("pre-event artifact denied -> no failure observed on this variant")
        label = "no weakness observed"
    return {
        "observed_decision": decision,
        "classification": label,
        "mechanism_rule_path": meta["cwe_rule_path"],
        "neighbour_rules": dict(meta["neighbour_rules"], **{
            "time-only (no explicit trigger)": "would route to CWE-613 original sense (insufficient expiration)",
            "login-time identifier reuse": "would route to CWE-384 (session fixation)",
        }),
    }


def run(out_dir=None, quiet=False):
    """Run the whole benchmark. Returns the canonical results object."""
    meta = load_metadata()
    started = time.time()
    per_mech, traces = [], {}
    for mech in MECHANISMS:
        row = {"id": mech.id, "title": meta[mech.id]["title"],
               "paper_class": meta[mech.id].get("paper_class"),
               "lifecycle_family": meta[mech.id].get("lifecycle_family"),
               "artifact_type": meta[mech.id]["artifact"]["type"],
               "termination_trigger": meta[mech.id].get("lifecycle_event", meta[mech.id]["termination_trigger"]),
               "normative_basis": meta[mech.id].get("normative_basis"),
               "uncertainty": meta[mech.id]["uncertainty"]["level"]}
        for variant in VARIANTS:
            summary, trace = run_scenario(mech, variant, meta[mech.id])
            row[variant] = summary
            traces["%s_%s" % (mech.id, variant)] = trace
        row["negative_control_failures"] = row["vulnerable"]["negative_control_failures"] + row["fixed"]["negative_control_failures"]
        row["clean"] = bool(row["vulnerable"]["pov_confirmed"] and row["fixed"]["pof_confirmed"]
                            and row["negative_control_failures"] == 0)
        per_mech.append(row)
        if not quiet:
            print(_console_line(row))

    results = {
        "schema": "sesstrace-results/2.0",
        "benchmark": "SessTrace",
        "version": __version__,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "python": platform.python_version(),
        "invariant": INVARIANT,
        "definitions": {
            "PoV": "on the vulnerable variant a valid scoped replay semantically completes the protected operation",
            "PoF": "on the fixed variant the invariant PASSES (replay is denied)",
            "negative_control_failure": "a negative check (a: pre-termination legitimate use, b: fresh login after termination, "
                                        "c: unrelated user) whose legitimate operation did not semantically succeed; "
                                        "not a detector false-positive metric",
        },
        "mechanisms": per_mech,
        "summary": {
            "n_mechanisms": len(per_mech),
            "pov_confirmed": sum(1 for r in per_mech if r["vulnerable"]["pov_confirmed"]),
            "pof_confirmed": sum(1 for r in per_mech if r["fixed"]["pof_confirmed"]),
            "negative_control_failures": sum(r["negative_control_failures"] for r in per_mech),
            "n_scenarios": len(traces),
            "n_http_steps": sum(t["steps"].__len__() for t in traces.values()),
            "all_clean": all(r["clean"] for r in per_mech),
            "elapsed_s": round(time.time() - started, 2),
        },
    }
    if out_dir:
        _write_outputs(out_dir, results, traces)
    if not quiet:
        s = results["summary"]
        print("-" * 78)
        print("mechanisms=%d  PoV confirmed=%d/%d  PoF confirmed=%d/%d  negative-control failures=%d  "
              "HTTP steps=%d  all_clean=%s" % (s["n_mechanisms"], s["pov_confirmed"], s["n_mechanisms"],
                                              s["pof_confirmed"], s["n_mechanisms"], s["negative_control_failures"],
                                              s["n_http_steps"], s["all_clean"]))
        if out_dir:
            print("outputs: %s" % out_dir)
    return results


def _console_line(row):
    v, f = row["vulnerable"], row["fixed"]
    return ("%s  vulnerable: pre=%s term=%s replay=%s inv=%-4s PoV=%-5s | fixed: pre=%s term=%s replay=%s inv=%-4s "
            "PoF=%-5s | NCF=%d | %s" % (row["id"], v["pre_termination_status"], v["termination_status"],
                                        v["replay_status"], v["invariant"], "OK" if v["pov_confirmed"] else "NO",
                                        f["pre_termination_status"], f["termination_status"], f["replay_status"],
                                        f["invariant"], "OK" if f["pof_confirmed"] else "NO",
                                        row["negative_control_failures"], row["title"]))


MATRIX_COLUMNS = ["mechanism", "title", "paper_class", "lifecycle_family", "artifact_type", "termination_trigger",
                  "vuln_pre_status", "vuln_termination_status", "vuln_replay_status", "vuln_invariant", "pov_confirmed",
                  "fixed_pre_status", "fixed_termination_status", "fixed_replay_status", "fixed_invariant", "pof_confirmed",
                  "neg_a_vuln", "neg_a_fixed", "neg_b_vuln", "neg_b_fixed", "neg_c_vuln", "neg_c_fixed",
                  "negative_control_failures", "uncertainty", "clean"]


def _matrix_row(r):
    v, f = r["vulnerable"], r["fixed"]

    def neg(s, key):
        return "PASS" if s["negatives"][key]["pass"] else "FAIL"
    return {
        "mechanism": r["id"], "title": r["title"], "paper_class": r.get("paper_class"),
        "lifecycle_family": r.get("lifecycle_family"), "artifact_type": r["artifact_type"],
        "termination_trigger": r["termination_trigger"],
        "vuln_pre_status": v["pre_termination_status"], "vuln_termination_status": v["termination_status"],
        "vuln_replay_status": v["replay_status"], "vuln_invariant": v["invariant"], "pov_confirmed": v["pov_confirmed"],
        "fixed_pre_status": f["pre_termination_status"], "fixed_termination_status": f["termination_status"],
        "fixed_replay_status": f["replay_status"], "fixed_invariant": f["invariant"], "pof_confirmed": f["pof_confirmed"],
        "neg_a_vuln": neg(v, "a_pre_termination_legit_works"), "neg_a_fixed": neg(f, "a_pre_termination_legit_works"),
        "neg_b_vuln": neg(v, "b_fresh_login_after_termination"), "neg_b_fixed": neg(f, "b_fresh_login_after_termination"),
        "neg_c_vuln": neg(v, "c_unrelated_user_unaffected"), "neg_c_fixed": neg(f, "c_unrelated_user_unaffected"),
        "negative_control_failures": r["negative_control_failures"], "uncertainty": r["uncertainty"], "clean": r["clean"],
    }


def _write_outputs(out_dir, results, traces):
    tdir = os.path.join(out_dir, "traces")
    os.makedirs(tdir, exist_ok=True)
    with open(os.path.join(out_dir, "benchmark_results.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(results, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(os.path.join(out_dir, "benchmark_matrix.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MATRIX_COLUMNS, lineterminator="\n")
        w.writeheader()
        for r in results["mechanisms"]:
            w.writerow(_matrix_row(r))
    for name, t in traces.items():
        with open(os.path.join(tdir, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(t, f, indent=2, sort_keys=True)
            f.write("\n")
    with open(os.path.join(out_dir, "artifact_inventory.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["mechanism", "variant", "artifact_id", "type", "holder", "issued_at_step", "value_prefix",
                    "under_test", "presented_at_steps", "termination_completion_step", "presented_after_termination",
                    "residual_capability_after_termination", "note"])
        for name, t in traces.items():
            term_step = t["termination"]["completion_step"]
            for a in t["artifact_inventory"]:
                after = [s for s in a["presented_at_steps"] if term_step is not None and s > term_step]
                under_test = a["id"] == t["artifact_under_test"]
                w.writerow([t["mechanism"]["id"], t["variant"], a["id"], a["type"], a["holder"], a["issued_at_step"],
                            a["value_prefix"], under_test, " ".join(map(str, a["presented_at_steps"])), term_step,
                            bool(after), t["replay"]["residual_capability"] if under_test else "", a["note"]])

