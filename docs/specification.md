# The specification file

A specification is one JSON file. `sesstrace spec check <file>` reports what is wrong with it; `sesstrace spec list <file>`
lists its entries.

## Top level

| Key | Meaning |
|---|---|
| `targets` | the list of entries (required) |
| `repeats_per_revision` | runs per entry and revision; when present, the records use the cells layout |
| `scope` | free text copied into every evaluation: what the results do and do not say (required by the evaluator) |
| `contract_lifecycle_condition` | cells layout: the class each contract stands for, used by the reading |
| `reading_rule` | cells layout: free text, how the reading is meant |
| `target_setup` | what the runners need per target: image, repository or release, commands, port |

Other keys are documentation for the reader (study, verdict rule, status when written) and are ignored by the package.

## An entry

```json
{
  "id": "T8.lifetime",
  "target": "T8",
  "contract": "lifetime",
  "cve": "CVE-2024-55603",
  "package": "Kanboard",
  "frozen_v2_class": "T",
  "expected_category": "FLIPS",
  "vulnerable_commit": "sha256:...",
  "fixed_commit": "sha256:...",
  "lifetime_seconds": 30,
  "boundary_wait_seconds": 75,
  "plan": [ ... ],
  "replay_checkpoints": ["replay_after_lifetime"],
  "control_checkpoints": ["pre_alice", "control_unexpired_other_user", "control_fresh_login_after_lifetime", "control_unknown_credential"],
  "replay_requires": {},
  "expected": {
    "vulnerable": {"pre_alice": "success", "control_unexpired_other_user": "success", "control_fresh_login_after_lifetime": "success", "control_unknown_credential": "denied", "replay_after_lifetime": "success"},
    "fixed":      {"pre_alice": "success", "control_unexpired_other_user": "success", "control_fresh_login_after_lifetime": "success", "control_unknown_credential": "denied", "replay_after_lifetime": "denied"}
  },
  "source_basis": ["file and line of each revision that every expectation was read from"]
}
```

This is the cell `T8.lifetime` of `checks/phase3/SPEC_CELLS_D.json` with the plan and the digests left out.

- `id` names the entry on the command line and in file names. In the cells layout it is `<target>.<contract>`.
- `vulnerable_commit` and `fixed_commit` are what the set-up record must show as `head=`: a commit hash for a library,
  an image digest for an application.
- `expected` gives one outcome word per checkpoint and revision: `success`, `denied`, `reported` or `other`.
- `replay_checkpoints` are judged for the verdict; in the cells layout the first one is the replay of the cell.
- `control_checkpoints` must come out as expected for a run to be valid.
- `replay_requires` names further checkpoints that must hold for the replay invariant in the summary to count.
- Numbers such as `lifetime_seconds` are referred to by name from plan steps.

## Plan steps

Every step has a `phase` (a label written into the trace) and a kind, `do`.

| `do` | Fields | What happens |
|---|---|---|
| `login` | `user`, `as`, `artifact` | `GET /login?user=<user>`; the cookie is kept under the name `artifact` |
| `profile` | `artifact`, `as`, `checkpoint` | `GET /profile` with that cookie; outcome `success`, `denied` or `other` |
| `logout` | `artifact`, `as`, `checkpoint` | `GET /logout` with that cookie; outcome `reported` or `other` |
| `wait_since` | `artifact`, `seconds` | wait until `entry[seconds]` have passed since that login |
| `event` | `path`, `field`, `as`, `checkpoint` | `GET <path>` without a cookie; `reported` when the answer is 200 and `field` is true |
| `profile_unknown` | `user`, `as`, `checkpoint` | `GET /profile` with a random value that was never issued |
| `profile_background` | `artifact`, `as`, `handle`, `path` | send one profile request on a second thread and go on |
| `pause` | `seconds` | sleep for `entry[seconds]` |
| `join` | `handle`, `checkpoint`, `spans_checkpoint` | wait for the background request, judge it, and record whether it was sent before and answered after the request of `spans_checkpoint` |

`as` is the actor written into the trace, for example `attacker (replaying alice1)`. An optional `note` is copied into the
trace as well.

The checkpoint named `pre_alice` is the first use of the credential that is later replayed; the replay invariant and the
audit both refer to it by this name.

## Records

One run per entry and revision (no `repeats_per_revision`):

```
<results>/setup_<id>_<revision>.txt        head=<commit>, install_exit=0, host_ready=1
<results>/summary_<id>_<revision>.json
<results>/trace_<id>_<revision>.json
```

Several runs per cell (`repeats_per_revision`):

```
<results>/setup_<target>_<revision>.txt    head=<commit or digest>, install_exit=0, run_<NN>_<cell>_host_ready=1 per run
<results>/<cell>/<revision>/run_<NN>/summary_<cell>_<revision>.json
<results>/<cell>/<revision>/run_<NN>/trace_<cell>_<revision>.json
```

The set-up records are written by the runner, not by the driver: they say what was installed and whether the target came
up, which the driver cannot know.

## Writing expectations

Expectations are written from the source of the two revisions, with file and line in `source_basis`, before anything is
run. Write them for every checkpoint, including the controls. If reading the source does not settle an outcome, say so in
the entry and expect what the documentation states; do not run first and write afterwards.
