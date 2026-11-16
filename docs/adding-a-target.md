# Adding a target

A target is a piece of software at two revisions: the one before a repair and the one after it. The work is the same for
a library and for an application; only the piece that speaks the endpoint contract differs.

## 1. Choose the contracts

List the events the target has: logout, a configurable lifetime, password change, disabling an account, deleting a grant.
Each event the target offers through its own interface is one cell. An event the target does not offer is written down
as not run, with the reason; it is not simulated.

## 2. Make the target speak the contract

**A library** gets a host application: the smallest program that mounts the library and maps `/login`, `/profile` and
`/logout` onto its session API (see `checks/external_targets/hosts/` and `checks/phase2/hosts/`). Rules that have served
well:

- load the library from the checkout given on the command line, never from a package index;
- take lifetimes from the command line, so that a plan can use seconds instead of hours;
- no logic of its own: if the host decides who is logged in, the check tests the host.

**An application** gets an adapter: a small HTTP server that translates each contract request into the application's own
requests (see `checks/phase3/adapters/`). Rules:

- pass the application's credential through unchanged as the cookie `sid`;
- answer `401 {"error": "no_session"}` only for the one not-logged-in answer written in the specification, and
  `502 {"error": "unrecognized"}` for everything else, so that an unexpected answer can never look like a refusal;
- keep no table of sessions;
- write one line per request sent to the application into a log, so that every answer of the adapter can be traced back.

A set-up script creates the two users through the application's documented interface. Passwords are generated per run.

## 3. Write the specification

Follow [specification.md](specification.md). Read both revisions and write the expected outcome of every checkpoint with
the file and line it was read from. Then:

```bash
sesstrace spec check my_spec.json
```

## 4. Try the plan against a stub

Before any real software runs, drive the plan against a stub that behaves as the specification says, and against one
that deviates. `tests/stubs.py` has three stubs and `tests/scenarios.py` runs whole series against them. A plan that
cannot tell a repairing stub from a non-repairing one will not tell real revisions apart either.

## 5. Freeze, then run

```bash
sesstrace freeze write . my_target --reason "written before the first request" my_spec.json hosts/my_host.py run.sh
sesstrace freeze check . my_target
```

Start the target in a disposable container, wait for `/ready`, write the set-up record (`head=`, `install_exit=`,
`host_ready=`), and run:

```bash
sesstrace run --spec my_spec.json --entry T9.logout --revision vulnerable --base http://127.0.0.1:18101 --out results/
```

The runners in `checks/run/` show the whole sequence for libraries and for applications.

## 6. Evaluate and audit

```bash
sesstrace evaluate --spec my_spec.json --results results/ --out evaluation.json
sesstrace audit    --spec my_spec.json --results results/
sesstrace report   evaluation.json
```

Report what came out, including the cells that did not confirm. If the set-up had to be repaired, keep the first run,
add a freeze block for the repair and say what changed.
