# SessTrace

SessTrace checks one property of software that issues sessions or tokens: **after the authority behind a credential has been
withdrawn, a copy of that credential must stop working.** The withdrawal can be a logout, the end of a configured lifetime, a
password change, a disabled account or a deleted grant.

It does this by replay. A plan logs a user in, copies the credential, lets the event happen, presents the copy again and
records what came back. The same plan is run against selected pinned affected and repaired revisions. The expected
outcome of every step is written down and hashed before the first request is sent.

**At a glance (version 3.1.1)**

- Eight synthetic mechanisms, each in a vulnerable and a fixed variant: 16 scenarios and 399 recorded HTTP steps,
  reproduced byte for byte by `sesstrace lab verify`.
- Eight public projects, each at an affected and a repaired revision: 23 checks, of which 22 came out as written down
  before the run.
- In 7 of those checks the copied credential still works before the repair and is refused after it.
- Every published result can be recomputed from the archived records without contacting any target.
- Standard library only; 145 tests.

The package is pure Python (3.7 or later), uses the standard library only, and has three parts.

| Part | What it is | Command |
|---|---|---|
| Laboratory | Eight synthetic mechanisms (M1 to M8) on loopback HTTP, each in a vulnerable and a fixed variant | `sesstrace lab run`, `sesstrace lab verify` |
| Replay engine | Driver, evaluator and audit for plans run against real software | `sesstrace run`, `sesstrace evaluate`, `sesstrace audit`, `sesstrace compare`, `sesstrace merge` |
| Checks | Eight public targets (four libraries, four applications), their frozen specifications and the records of 262 attempts (250 valid runs) | `checks/` |

## Quick start

No installation is needed for the tests, the laboratory or the reanalysis of the archived records. The source is
available in two places, and both hold the same release.

From the repository:

```bash
git clone https://github.com/abdullahzarshaid/sesstrace
cd sesstrace
```

From the supplementary archive of the article (extract `Supplement.zip` and open a shell in its top-level directory):

```bash
cd revision_addendum/sesstrace_package_3.1.1
```

Then, in either copy:

```bash
python -m unittest                      # the whole test suite, no installation needed
PYTHONPATH=src python -m sesstrace lab verify
```

The commands here use a POSIX shell and a Python 3 interpreter named `python`. Use `python3` if that is the interpreter
name on your machine. Set `PYTHONPATH` to the package's `src` directory when using another shell.

Read the published checks again from their records, without installing the package:

```bash
PYTHONPATH=src python -m sesstrace evaluate --spec checks/phase3/SPEC_CELLS_D.json --results checks/records/application_cells/results --out evaluation.json
PYTHONPATH=src python -m sesstrace audit    --spec checks/phase3/SPEC_CELLS_D.json --results checks/records/application_cells/results
PYTHONPATH=src python -m sesstrace report   checks/records/library_cells/evaluation.json checks/records/application_cells/evaluation.json checks/records/application_cells_second/evaluation.json checks/records/application_cells_third/evaluation.json
```

An optional installation provides the shorter `sesstrace` command:

```bash
python -m pip install -e .
sesstrace lab verify
```

Installation uses the build dependency `setuptools>=61` and may download build tools. If compatible build tools are
already installed, `python -m pip install --no-build-isolation --no-deps -e .` uses those local tools; the no-installation
commands above are the supported path when working offline. Running the public-software container checks is a separate
operation and can require third-party images and source downloads; see [checks/README.md](checks/README.md).

## A concrete archived check

The archived `T2.lifetime` cell checks `@fastify/secure-session` at the two pinned revisions for CVE-2024-31999. Its plan
sets a five-second session lifetime, waits at least ten seconds, and sends `GET /profile` with the same copied cookie.
The expected answer is success at the affected revision and denial at the repaired revision. Pre-expiry use, a separate
unexpired user and a fresh login are checked as controls.

These commands recompute the library-series evaluation from retained JSON records. They do not send target requests or
start containers:

```bash
PYTHONPATH=src python -m sesstrace evaluate \
  --spec checks/phase3/SPEC_CELLS.json \
  --results checks/records/library_cells/results \
  --out library_evaluation.json
PYTHONPATH=src python -m sesstrace audit \
  --spec checks/phase3/SPEC_CELLS.json \
  --results checks/records/library_cells/results
PYTHONPATH=src python -m sesstrace report library_evaluation.json
```

The evaluator's `T2.lifetime` entry is `["CONFIRMED", "FLIPS"]`. The archived records contain ten valid runs at each
revision: all ten affected replays were accepted, and all ten repaired replays were denied. In `run_01`, the copied
artifact `A1` returned `200` with `sub=alice` before expiry on both revisions; after expiry it returned `200` with
`sub=alice` on the affected revision and `401` with `error=no_session` on the repaired revision. All three controls
succeeded. The complete traces are under `checks/records/library_cells/results/T2.lifetime/`.

The audit command above prints the following summary for the complete eight-cell library series:

```text
160 runs, 1360 requests read, 0 problem(s), 0 run(s) without records, 0 request(s) not sent
```

`CONFIRMED` means that the observed cell matches its prespecified outcome. For this cell that outcome is `FLIPS`.
A different contract on the same target, `T2.logout`, is confirmed as `ACCEPTED_AT_BOTH`; the selected repair enforces a
lifetime boundary, and the observations do not establish logout revocation.

## How a check works

1. **Specification.** One JSON file per series. Each entry is a cell: one target under one contract (logout, lifetime,
   concurrent logout, credential change, account disabled, grant withdrawn). It holds the plan, the checkpoints, and the
   outcome expected at every checkpoint of the vulnerable and of the fixed revision. See
   [docs/specification.md](docs/specification.md).
2. **Freeze.** The specification and every script that will run are hashed into a block of `FREEZE_LOG.txt` before the
   target receives a request. The runners refuse to start when a frozen file has changed. A repair adds a new block; no
   block is edited.
3. **Target.** A library is placed behind a host application of at most 80 lines; a complete application is placed behind
   an adapter of at most 150 lines. Both speak one small endpoint contract (`/login`, `/profile`, `/logout`), so the driver
   never needs to know the target.
4. **Run.** `sesstrace run` sends the plan and writes a summary and a trace. The trace holds one record per request;
   credential values are never written.
5. **Evaluate.** `sesstrace evaluate` compares the records with the specification. A run counts only when the pinned
   revision was installed, the target was ready, every control came out as expected and no request failed. A cell is
   `CONFIRMED` when every run is valid and every replay is as expected, `NOT_CONFIRMED` when a valid run differs, and
   `INCONCLUSIVE` otherwise. Expectations are never changed after a run.
6. **Audit.** `sesstrace audit` reads the traces and checks that the requests really were the plan, in order, with the
   right credential, and that every summary agrees with its trace.

The method, the verdict rule and the controls are described in [docs/method.md](docs/method.md).

## The checks on public software

Eight targets from a fixed screening list, each at selected pinned affected and repaired revisions associated with one published CVE.

| | Target | Language | Vulnerable and fixed revision | CVE |
|---|---|---|---|---|
| T1 | @fastify/session | JavaScript | commits `8b6241c`, `0495ce5` | CVE-2024-35220 |
| T2 | @fastify/secure-session | JavaScript | commits `7b6eebe`, `56d6664` | CVE-2024-31999 |
| T3 | aiohttp-session | Python | commits `faadf10`, `1b356f0` | CVE-2018-1000814 |
| T4 | rack-session | Ruby | commits `c837aff`, `c28c4a8` | CVE-2025-46336 |
| T5 | Vikunja | Go | releases 2.2.2, 2.3.0 | CVE-2026-35594 |
| T6 | FUXA | JavaScript | releases 1.3.2, 1.3.3 | CVE-2026-65984 |
| T7 | Directus | TypeScript | releases 10.10.7, 10.11.0 | CVE-2024-34709 |
| T8 | Kanboard | PHP | releases 1.2.42, 1.2.43 | CVE-2024-55603 |

Across the eight targets there are 23 cells, 262 attempts and 2,326 recorded requests. Twelve attempts were invalid because
of setup conditions, leaving 250 valid runs. The table reports each cell after the documented setup retries; both the
initial invalid attempts and the valid repeat series remain in the archive.

| Result | Cells |
|---|---|
| Matched the specification in the final valid series (`CONFIRMED`) | 22 |
| A valid run differs from the specification (`NOT_CONFIRMED`) | 1 |
| No valid run (`INCONCLUSIVE`) | 0 |

Of the 22 confirmed cells, in 7 the replay is accepted before the repair and refused after it, in 8 it is accepted at both
revisions and in 7 it is refused at both.

One cell did not come out as specified, and it is kept as it is:

- **T7 logout.** The fixed release answered the replay with HTTP 403. The specification had named HTTP 401 as the
  not-logged-in answer of this application, so the adapter reported an unrecognised answer. The runs are valid and the
  cell is `NOT_CONFIRMED`; the expectation was not reinterpreted afterwards.

Two cells were attempted a second time, because their first attempt had no valid run for a reason in the set-up. The plan
and the expectations stayed as they were, and both attempts of each cell are in the records:

- **T7 credential change.** The role created by the set-up was not allowed to change its own password. With that
  permission granted the cell came out as specified.
- **T5 grant withdrawn.** A control login was refused by the rate limit of the application (HTTP 429) in every run. With
  the documented limit of the application raised, all six runs were valid: the copied share token was accepted before the
  repair and refused after it.

For FUXA, the adapter checks `POST /api/refresh` and the returned username. It does not use a newly issued credential
to attempt a subsequent protected-resource request, so the retained result is limited to that endpoint-level check.

These are observations on the named old releases under one configuration each. They are not statements about current
versions, and a replay that is accepted at both revisions of a contract the repair did not address is reported as an
observation, not as a vulnerability. The checks are not a detection rate and not a benchmark of the targets.

The laboratory itself was run in 15 official container images (ten Linux distribution releases, Python 3.10 to 3.15,
glibc and musl) and gave identical output in each. A line witness for four cells confirmed that the replay reached the
refusing line of the repair exactly as often as stated in advance. Everything is listed in [checks/README.md](checks/README.md).

## Where the results come from

The runs in `checks/records/` were made on 14, 15 and 17 November 2026 with the scripts that were frozen for each series at
the time; those scripts are part of the supplementary material of the manuscript. This package is the maintained form of
the same method. Three things tie the two together, and the test suite checks each of them:

- the laboratory reproduces the twelve archived trace files byte for byte and the archived expiration result;
- the evaluator, run over the archived records, writes the archived evaluation files byte for byte;
- the host applications, adapters, set-up scripts and specifications in `checks/` are the frozen files, unchanged.

On 17 November 2026, version 3.0.0 repeated 256 cell attempts and 2,266 recorded requests, and the laboratory gave
identical output in all 15 images; see [checks/release_test_20261117/README.md](checks/release_test_20261117/README.md).
Version 3.1.0 completed the six-run third application series during the runner check on 17 November UTC (18 November
local time), bringing the combined repeat to 262 attempts and 2,326 requests. Every cell reproduced its original
verdict, category and valid replay counts. These repeats used the same team and Kali machine. Version 3.1.1 runner
changes were tested with a stand-in container engine, without a complete container rerun; see
[checks/runner_check_20261118/README.md](checks/runner_check_20261118/README.md). A fresh run needs a Linux machine with
a container engine; see [checks/README.md](checks/README.md).

## Safety

The laboratory and the tests use loopback only. The checks download and run third-party software at old, vulnerable
revisions. **Run them only in a disposable, unprivileged local container or virtual machine. Do not use production
servers, private credentials or targets you are not allowed to test.** The runners use containers without
`--privileged`, without host networking and without published ports; the application runs use a network with no route
out.

## Layout

```
src/sesstrace/          the package
  trace.py              request recorder with redaction
  outcome.py            typed outcome of an operation and the replay verdict
  lab/                  synthetic laboratory, its metadata and reference output
  replay/               spec, freeze, driver, merge, evaluate, audit, witness
  cli.py                command line
checks/                 the eight public targets
  external_targets/, phase2/, phase3/, phase3b/, phase3c/    frozen specifications, hosts, adapters, set-up scripts
  records/              set-up records, summaries, traces and evaluations of the published runs
  release_test_20261117/    the evaluations of a fresh run of every series with this package
  runner_check_20261118/    the results of a second run, of the runner changes made after the first
  run/                  container runners for a Linux machine
tests/                  unit tests (standard library unittest)
docs/                   method, specification format, adding a target, laboratory
```

## Limits

- The driver speaks cookie-carried credentials over one small contract; anything else needs a host application or an adapter.
- A verdict is about one plan, one configuration and two revisions. It says nothing about other paths of the same software.
- The laboratory is synthetic. It demonstrates the mechanisms and exercises the recorder; it is not a model of any product.
- The container runners are written for Linux with Docker; no other system was tested. They were run from start to end on
  17 November 2026 and their later changes on 18 November. Three small changes made after that (an exit status, a freeze
  check before a merge, one field of the build record) were exercised against a stand-in for the engine only.

## Author and citing

SessTrace is written and maintained by Abdullah Bin Zarshaid.

The method and the results are described in a manuscript under review:
*Lifecycle Conditions in CWE-613 Disclosures: A Reproducible, Evidence-Linked Characterisation*
(A. Bin Zarshaid, S. A. Siddiqui, A. Khaliq, G. Ahmed, F. Ullah and S. Kamal).
The manuscript also states how the software and the specifications were prepared and checked. Citation data is in
[CITATION.cff](CITATION.cff); it will be updated when the article has a DOI.

## Security

How to report a problem in SessTrace, and how to use it safely, is in [SECURITY.md](SECURITY.md).

## Licence

MIT; see [LICENSE](LICENSE). The third-party software the checks download is not part of this repository and keeps its
own licences.
