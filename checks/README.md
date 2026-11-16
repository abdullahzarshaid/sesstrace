# The checks on public software

This folder holds everything about the eight public targets: what was specified, what was run, what came back, and the
scripts to run it again.

## Folder names

The folders keep the names of the archive in which the specifications were frozen, because the specifications name their
host applications, adapters and set-up scripts by those paths. Every file in these four folders is byte-identical to the
frozen one; the digests are in `records/freeze_logs/`.

| Folder | Series | Content |
|---|---|---|
| `external_targets/` | first single runs (T1, T2), 14 November 2026 | `EXTERNAL_SPEC.json`, two host applications |
| `phase2/` | second single runs (T3, T4), 15 November 2026 | `EXTERNAL_SPEC_PHASE2.json`, two host applications |
| `phase3/` | library cells, line witness, distributions, application cells, 15 November 2026 | `SPEC_CELLS.json`, `SPEC_WITNESS.json`, `MATRIX_PLAN.json`, `SPEC_CELLS_D.json`, adapters, set-up scripts, counting helpers, Dockerfiles |
| `phase3b/` | two further application cells, 15 November 2026 | `SPEC_CELLS_3B.json`, one adapter, two set-up scripts |

Comments inside those files use the labels of the time: "phase 1" and "phase 2" are the two single-run series, "part A" is
the distribution matrix, "part B" the library cells, "part C" the line witness, "part D" the application cells, and
"phase 3b" the two further application cells.

`series.json` lists the series in the order they were run, with the digest of each specification.

## Records

`records/` holds the files the package reads, copied unchanged from the archive of the runs (`SHA256SUMS.txt` lists them):

| Folder | Runs | What the series shows |
|---|---|---|
| `libraries_single_run_1/`, `libraries_single_run_2/` | 4 + 4 | each library once per revision |
| `library_cells/` | 160 | 8 cells of the four libraries, 10 runs per revision |
| `application_cells/` | 84 | 14 cells of the four applications, 3 runs per revision |
| `application_cells_second/` | 12 | T5.grant_withdrawn, and the second attempt of T7.credential_change |
| `line_witness/` | 8 | one counted run per revision of four library cells |
| `distributions/` | 15 images | the laboratory on ten Linux distribution releases |
| `freeze_logs/` | | the freeze logs as they were written before each series |

Each series folder has `results/` (set-up records, summaries, traces) and `evaluation.json` (the evaluation written at the
time). The first attempt of T7.credential_change, in `application_cells/`, had no valid run because the set-up lacked one
permission; the second attempt, with the plan and the expectations unchanged, is the one reported.

Logs, consoles, raw coverage and container records are not copied here. They are in the supplementary material of the
manuscript.

To read the records again:

```bash
python -m unittest tests.test_records                      # everything below, as tests
sesstrace evaluate --spec checks/phase3/SPEC_CELLS.json --results checks/records/library_cells/results --out /tmp/evaluation.json
sesstrace audit    --spec checks/phase3/SPEC_CELLS.json --results checks/records/library_cells/results
sesstrace witness evaluate --cells checks/phase3/SPEC_CELLS.json --spec checks/phase3/SPEC_WITNESS.json --results checks/records/line_witness --out /tmp/witness.json
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
| Laboratory on several distributions | `distributions` | `bash checks/run/distributions.sh build <out1>` then `bash checks/run/distributions.sh run <out2>` |

`applications.sh ... boot <target>` starts an application once, runs its set-up and asks the adapter for `/ready`
without sending any checkpoint. Use it to see that an application starts before a run is spent on it.

A runner writes into a new output folder and refuses an existing one. At the end it evaluates and audits the run
without network; the evaluation is `evaluation.json`. A fresh run is compared with the published one by the verdict and
the category of every cell, not byte for byte: times, ports and request counts of the applications differ between runs.

## What a deviation means

A cell that does not come out as specified is a result, not a defect to be repaired. The specification is not edited to
fit a run. When a set-up has to be repaired, for example because a release refuses to start with a setting, only the
set-up may change, a new freeze block is written, and both runs are kept.
