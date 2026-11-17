# The checks on public software

This folder holds everything about the eight public targets: what was specified, what was run, what came back, and the
scripts to run it again.

## Folder names

The folders keep the names of the archive in which the specifications were frozen, because the specifications name their
host applications, adapters and set-up scripts by those paths. Every file in these five folders is byte-identical to the
frozen one; the digests are in `records/freeze_logs/`.

| Folder | Series | Content |
|---|---|---|
| `external_targets/` | first single runs (T1, T2), 14 November 2026 | `EXTERNAL_SPEC.json`, two host applications |
| `phase2/` | second single runs (T3, T4), 15 November 2026 | `EXTERNAL_SPEC_PHASE2.json`, two host applications |
| `phase3/` | library cells, line witness, distributions, application cells, 15 November 2026 | `SPEC_CELLS.json`, `SPEC_WITNESS.json`, `MATRIX_PLAN.json`, `SPEC_CELLS_D.json`, adapters, set-up scripts, counting helpers, Dockerfiles |
| `phase3b/` | two further application cells, 15 November 2026 | `SPEC_CELLS_3B.json`, one adapter, two set-up scripts |
| `phase3c/` | further attempt of one application cell, 17 November 2026 | `SPEC_CELLS_3C.json`; the adapter and the set-up script are those of `phase3b/` |

Comments inside those files use the labels of the time: "phase 1" and "phase 2" are the two single-run series, "part A" is
the distribution matrix, "part B" the library cells, "part C" the line witness, "part D" the application cells, and
"phase 3b" the two further application cells and "phase 3c" the further attempt of T5.grant_withdrawn.

`series.json` lists the series in the order they were run, with the digest of each specification.

## Records

`records/` holds the files the package reads, copied unchanged from the archive of the runs (`SHA256SUMS.txt` lists them):

| Folder | Runs | What the series shows |
|---|---|---|
| `libraries_single_run_1/`, `libraries_single_run_2/` | 4 + 4 | each library once per revision |
| `library_cells/` | 160 | 8 cells of the four libraries, 10 runs per revision |
| `application_cells/` | 84 | 14 cells of the four applications, 3 runs per revision |
| `application_cells_second/` | 12 | T5.grant_withdrawn, and the second attempt of T7.credential_change |
| `application_cells_third/` | 6 | the further attempt of T5.grant_withdrawn |
| `line_witness/` | 8 | one counted run per revision of four library cells |
| `distributions/` | 15 images | the laboratory on ten Linux distribution releases |
| `freeze_logs/` | | the freeze logs as they were written before each series |

Each series folder has `results/` (set-up records, summaries, traces) and `evaluation.json` (the evaluation written at the
time). Two cells were attempted twice, with the plan and the expectations unchanged, and the later attempt is the one
reported. The first attempt of T7.credential_change, in `application_cells/`, had no valid run because the set-up lacked one
permission. The first attempt of T5.grant_withdrawn, in `application_cells_second/`, had no valid run because the
application answered a control with HTTP 429 from its own rate limit; the further attempt raises that limit through the
setting the project documents and changes nothing else, which `tests/test_records.py` checks.

Logs, consoles, raw coverage and container records are not copied here. They are in the supplementary material of the
manuscript.

To read the records again:

```bash
python -m unittest tests.test_records                      # everything below, as tests
sesstrace evaluate --spec checks/phase3/SPEC_CELLS.json --results checks/records/library_cells/results --out /tmp/evaluation.json
sesstrace audit    --spec checks/phase3/SPEC_CELLS.json --results checks/records/library_cells/results
sesstrace witness evaluate --cells checks/phase3/SPEC_CELLS.json --spec checks/phase3/SPEC_WITNESS.json --results checks/records/line_witness --out /tmp/witness.json
sesstrace witness audit    --cells checks/phase3/SPEC_CELLS.json --spec checks/phase3/SPEC_WITNESS.json --results checks/records/line_witness
```

## Running the checks again

The runners in `run/` need Linux, bash, Python 3.7 or later, git and a container engine (Docker; set
`CONTAINER_ENGINE` for another one with the same command line). They download third-party software at old, vulnerable
revisions.

**Run them only on a disposable machine or virtual machine that holds nothing of value. Do not point them at
production servers, and do not give them private credentials.** Every container is started without `--privileged`,
without host networking and without a published port. The applications run on a network created with `--internal`,
which has no route out. All passwords are generated per run inside a volume that is removed after the run.

Each series must be frozen before it is run. The freeze block lists the specification, the hosts or adapters, the
runner scripts and every source file of the package:

```bash
bash checks/run/freeze.sh libraries "written before the first request of this run"
git add FREEZE_LOG.txt && git commit -m "Freeze the library cells"
bash checks/run/libraries.sh /path/to/new/output/folder
```

| Series | Freeze block | Command |
|---|---|---|
| Library cells | `libraries` | `bash checks/run/libraries.sh <out>` |
| Line witness | `witness` | `bash checks/run/witness.sh <out>` |
| Application cells | `applications_first` | `bash checks/run/applications.sh first <out> run T5 T6 T7 T8` |
| Further application cells | `applications_second` | `bash checks/run/applications.sh second <out> run T5 T7` |
| Further attempt of one cell | `applications_third` | `bash checks/run/applications.sh third <out> run T5` |
| Laboratory on several distributions | `distributions` | `bash checks/run/distributions.sh build <out1>` then `bash checks/run/distributions.sh run <out2>` |

`applications.sh ... boot <target>` starts an application once, runs its set-up and asks the adapter for `/ready`
without sending any checkpoint. Use it to see that an application starts before a run is spent on it.

A runner writes into a new output folder and refuses an existing one. At the end it evaluates and audits the run
without network; the evaluation is `evaluation.json`. The distribution runner writes no audit, because it replays
nothing: the evidence of an image is the byte comparison of its trace files with the reference. A fresh run is compared
with the published one by the verdict, the category and the counts of valid replays of every cell, not byte for byte,
because times and ports differ between runs:

```bash
sesstrace compare --counts checks/records/library_cells/evaluation.json <out>/evaluation.json
```

Things worth knowing before a run:

- **Images.** Every image is pinned by digest and pulled before use. When the registry cannot be reached and an image
  with that digest is already on the machine, that image is used and the pull record says so.
- **A release that could not be run.** `ONLY_REVISION=fixed` (or `vulnerable`) restricts an application run to one
  release. It is meant for a release whose image could not be fetched before any checkpoint was sent, never for a
  second try of a run that has an outcome. The two output folders are then put together and evaluated as one:
  `bash checks/run/merge.sh first <new out> <out of attempt 1> <out of attempt 2>`. The merge stops when a file is in
  both attempts, and when a frozen file of the series has changed since its freeze block.
- **Exit status.** `applications.sh` ends with status 3 when a release was skipped because its image could not be
  fetched. What could be run is still run and evaluated, and the host record names the release.
- **Distribution images.** The build reuses layers of an earlier build on the same machine, also after the derived
  images were removed. The build record states for every derived image how many steps came from the cache, of how
  many; `REBUILD=1 bash checks/run/distributions.sh build <out>` builds every step again and needs the package
  mirrors of the distributions.
- **Owner of the output.** Files written by the containers belong to root on the host. They are readable by everyone;
  removing an output folder needs root unless the engine runs without it.

The runners were run from start to end on 17 November 2026; the result is in
[release_test_20261117/README.md](release_test_20261117/README.md), with the defects that run found. The changes made
for those defects were run on 18 November; the result is in
[runner_check_20261118/README.md](runner_check_20261118/README.md). Three small changes made after that second run were
exercised against a stand-in for the container engine only: `bash tools/dry_run_runners.sh <empty folder>` repeats
that on any machine with bash, tar and Python, without a container engine and without running third-party code.

## What a deviation means

A cell that does not come out as specified is a result, not a defect to be repaired. The specification is not edited to
fit a run. When a set-up has to be repaired, for example because a release refuses to start with a setting, only the
set-up may change, a new freeze block is written, and both runs are kept.
