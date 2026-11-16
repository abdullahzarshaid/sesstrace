"""Reading and checking a replay specification.

A specification is a JSON file. Its list `targets` holds the entries that can
be run; an entry is either a whole target (one plan per target) or a cell (one
target under one contract). Every entry carries

    id                    name used on the command line and in file names
    plan                  the ordered steps the driver sends
    replay_checkpoints    the checkpoints that replay a credential copied earlier
    control_checkpoints   the checkpoints that must hold for a run to count
    expected              {"vulnerable": {...}, "fixed": {...}}: the outcome
                          expected at every checkpoint of each revision
    vulnerable_commit, fixed_commit
                          what the set-up record must show for each revision
                          (a commit hash for a library, an image digest for an
                          application)

The expectations are written before anything is run and are never edited
afterwards; see sesstrace.replay.freeze.
"""
from ..fileio import read_json

VARIANTS = ("vulnerable", "fixed")
STEP_KINDS = ("login", "profile", "logout", "wait_since", "profile_background", "pause", "join", "event", "profile_unknown")
CHECKPOINT_STEPS = ("profile", "logout", "join", "event", "profile_unknown")
OUTCOME_WORDS = ("success", "denied", "reported", "other")


def load(path):
    return read_json(path)


def entry(spec, entry_id):
    for candidate in spec.get("targets", []):
        if candidate.get("id") == entry_id:
            return candidate
    raise KeyError("no entry named %r in the specification" % entry_id)


def http_steps(plan):
    """The steps of a plan that send one HTTP request each."""
    return [step for step in plan if step["do"] in ("login", "profile", "logout", "event", "profile_unknown", "profile_background")]


def problems(spec):
    """Return a list of human-readable problems; an empty list means the specification is usable."""
    found = []
    entries = spec.get("targets")
    if not isinstance(entries, list) or not entries:
        return ["the specification has no list 'targets'"]
    seen = set()
    for item in entries:
        name = item.get("id", "<entry without id>")
        if name in seen:
            found.append("%s: the id is used twice" % name)
        seen.add(name)
        for key in ("plan", "replay_checkpoints", "control_checkpoints", "expected"):
            if key not in item:
                found.append("%s: missing '%s'" % (name, key))
        if any(key not in item for key in ("plan", "replay_checkpoints", "control_checkpoints", "expected")):
            continue
        checkpoints = []
        logins = set()
        for number, step in enumerate(item["plan"], 1):
            kind = step.get("do")
            if kind not in STEP_KINDS:
                found.append("%s: step %d has the unknown kind %r" % (name, number, kind))
                continue
            if kind == "login":
                logins.add(step.get("artifact"))
            if kind in ("profile", "logout", "profile_background", "wait_since") and step.get("artifact") not in logins:
                found.append("%s: step %d uses the credential %r before any login issued it" % (name, number, step.get("artifact")))
            if kind in CHECKPOINT_STEPS:
                if not step.get("checkpoint"):
                    found.append("%s: step %d (%s) names no checkpoint" % (name, number, kind))
                else:
                    checkpoints.append(step["checkpoint"])
            if kind in ("wait_since", "pause") and step.get("seconds") not in item:
                found.append("%s: step %d refers to the value %r, which the entry does not define" % (name, number, step.get("seconds")))
        if len(checkpoints) != len(set(checkpoints)):
            found.append("%s: a checkpoint name is used by more than one step" % name)
        named = set(item["replay_checkpoints"]) | set(item["control_checkpoints"])
        for checkpoint in sorted(named - set(checkpoints)):
            found.append("%s: checkpoint %r is not produced by any step of the plan" % (name, checkpoint))
        for variant in VARIANTS:
            expected = item["expected"].get(variant)
            if not isinstance(expected, dict):
                found.append("%s: no expectations for the %s revision" % (name, variant))
                continue
            for checkpoint in sorted(named - set(expected)):
                found.append("%s: no expected outcome for %r at the %s revision" % (name, checkpoint, variant))
            for checkpoint, word in expected.items():
                if word not in OUTCOME_WORDS:
                    found.append("%s: %r is not an outcome word (%s, %s)" % (name, word, checkpoint, variant))
            if variant + "_commit" not in item:
                found.append("%s: missing '%s_commit'" % (name, variant))
    return found
