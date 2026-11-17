# SessTrace

SessTrace checks one property of software that issues sessions or tokens: **after the authority behind a credential has been
withdrawn, a copy of that credential must stop working.** The withdrawal can be a logout, the end of a configured lifetime, a
password change, a disabled account or a deleted grant.

It does this by replay. A plan logs a user in, copies the credential, lets the event happen, presents the copy again and
records what came back. The same plan is run against the release before a repair and the release after it. The expected
outcome of every step is written down and hashed before the first request is sent.

The package is pure Python (3.7 or later), uses the standard library only, and has three parts.

| Part | What it is | Command |
|---|---|---|
| Laboratory | Eight synthetic mechanisms (M1 to M8) on loopback HTTP, each in a vulnerable and a fixed variant | `sesstrace lab run`, `sesstrace lab verify` |
| Replay engine | Driver, evaluator and audit for plans run against real software | `sesstrace run`, `sesstrace evaluate`, `sesstrace audit`, `sesstrace compare`, `sesstrace merge` |
| Checks | Eight public targets (four libraries, four applications), their frozen specifications and the records of 262 runs | `checks/` |

## Quick start

```bash
git clone <this repository>
cd sesstrace
python -m unittest                      # the whole test suite, no installation needed
python -m pip install -e .              # optional: gives the command `sesstrace`
sesstrace lab verify                    # run the laboratory and compare with the reference output
```

Without installing, the same commands work as `PYTHONPATH=src python -m sesstrace ...`.

Read the published checks again from their records:

```bash
sesstrace evaluate --spec checks/phase3/SPEC_CELLS_D.json --results checks/records/application_cells/results --out evaluation.json
sesstrace audit    --spec checks/phase3/SPEC_CELLS_D.json --results checks/records/application_cells/results
sesstrace report   checks/records/library_cells/evaluation.json checks/records/application_cells/evaluation.json checks/records/application_cells_second/evaluation.json checks/records/application_cells_third/evaluation.json
```

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

Eight targets from a fixed screening list, each at the release before and after the repair of one published CVE.

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

Across the eight targets there are 23 cells, 262 runs and 2,326 recorded requests.

| Result | Cells |
|---|---|
| As specified in every run (`CONFIRMED`) | 22 |
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

On 17 November 2026 every series of 14 and 15 November was run again with this package and its own runners. Each cell came
out with the published verdict, category and counts, and the laboratory gave identical output in all 15 images; see
[checks/release_test_20261117/README.md](checks/release_test_20261117/README.md). A fresh run needs a Linux machine with a
container engine; see [checks/README.md](checks/README.md).

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
  run/                  container runners for a Linux machine
tests/                  unit tests (standard library unittest)
docs/                   method, specification format, adding a target, laboratory
```

## Limits

- The driver speaks cookie-carried credentials over one small contract; anything else needs a host application or an adapter.
- A verdict is about one plan, one configuration and two revisions. It says nothing about other paths of the same software.
- The laboratory is synthetic. It demonstrates the mechanisms and exercises the recorder; it is not a model of any product.
- The container runners are written for Linux with Docker; no other system was tested. They were changed after the
  release test of 17 November 2026 and have not been run on a container engine since.

## Citing

The method and the results are described in a manuscript under review:
*Lifecycle Conditions in CWE-613 Disclosures: A Reproducible, Evidence-Linked Characterisation.*
The manuscript also states how the software and the specifications were prepared and checked. Citation data is in
[CITATION.cff](CITATION.cff); it will be updated when the article has a DOI.

## Licence

MIT; see [LICENSE](LICENSE). The third-party software the checks download is not part of this repository and keeps its
own licences.
