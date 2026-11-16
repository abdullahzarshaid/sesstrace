# Method

## The question

A credential (a session cookie, a token) carries authority that something can later withdraw: the user logs out, the
configured lifetime ends, the password is changed, the account is disabled, a grant is deleted. The question of a check
is always the same: **does a copy of the credential, taken before the event, still complete a protected operation after
the event?**

## The endpoint contract

The driver speaks one small contract, whatever the target is.

| Request | Answer that counts |
|---|---|
| `GET /login?user=alice` or `bob` | `200 {"logged_in": true}` and a cookie `sid` |
| `GET /profile` with `sid` | success: `200 {"sub": <that user>, "rp": "RP1"}`; denial: `401 {"error": "no_session"}` |
| `GET /logout` with `sid` | `200 {"logged_out": true}` |
| `GET <event path>` | `200` and the boolean field the plan names, for example `{"changed": true}` |
| `GET /ready` | `200`, used by the runners only |

A status code alone never counts. A `200` that names another user, or a `401` with another error, is neither success nor
denial; it is recorded as `other` and can make a run invalid, but it can never confirm a repair.

A library is given a host application that maps the contract onto the library's session API. A complete application is
given an adapter that maps each request onto the application's own login, identity request and logout, passes the
application's credential through unchanged as `sid`, and answers `401` only for the exact not-logged-in answer written in
the specification. Any other answer of the application becomes `502 {"error": "unrecognized"}`. The adapter keeps no
session table of its own, so it cannot make a decision the application did not make.

## A plan

A plan is a list of steps. A typical one:

1. Alice logs in; Bob logs in.
2. Alice's cookie works (`pre_alice`); Bob's works (`pre_bob`).
3. The event: Alice logs out (`termination`).
4. **Replay**: the copy of Alice's first cookie is presented again (`replay_after_logout`).
5. Controls: Bob's cookie still works; Alice can log in again and the new cookie works; a value that was never issued
   is refused.

The controls are what keeps a verdict honest. If Bob is logged out too, the target is simply down. If a value that was
never issued is accepted, then "accepted" means nothing. If the fresh login fails, a refusal of the replay may be a
broken target, not an enforced logout.

Step kinds: `login`, `profile`, `logout`, `wait_since` (wait until a time has passed since a login), `event`,
`profile_unknown`, and for races `profile_background`, `pause` and `join`. See [specification.md](specification.md).

## Validity of a run

A run is valid when all of these hold:

- the set-up record shows the pinned revision (commit hash or image digest) and a clean installation;
- the target became ready;
- every control checkpoint has the outcome the specification expects for that revision;
- no request failed in transport;
- every wait and pause lasted at least as long as required;
- a background request that had to span another request really was sent before it and answered after it.

## Verdict of a cell

| Verdict | Rule |
|---|---|
| `CONFIRMED` | every run is valid and every replay has the expected outcome |
| `NOT_CONFIRMED` | at least one valid run has a replay that differs from the expectation |
| `INCONCLUSIVE` | neither: some run is not valid and no valid run differs |

The observed category describes the replays of the valid runs at the two revisions: `FLIPS` (accepted before, refused
after), `ACCEPTED_AT_BOTH`, `REFUSED_AT_BOTH`, `MIXED`, or `NO_VALID_RUN`.

The expectation is part of the frozen specification. It is never edited to fit an observation; a mismatch is reported
as `NOT_CONFIRMED` with the observation beside it.

## Freeze

Before the first request, the specification and all scripts are hashed into a block of the freeze log with the time and a
reason. Runners check the block on the host and again inside each container, and stop on any difference. Repairs add a
block. The log therefore shows that the expectations existed before the outcomes.

## Audit

The evaluator reads summaries. The audit reads traces, which the recorder writes request by request, and checks that:

- the requests are the HTTP steps of the plan, in order and on the right paths;
- a login presents no credential and receives exactly one; an event presents none; the unknown-credential step
  presents a value that was never issued;
- the replay presents the credential of the first use, after it;
- every checkpoint of the summary points at the right request, with the same status and credential, and the outcome
  derived again from the trace is the outcome in the summary.

When a login issues nothing, the driver does not send the later requests that needed its credential; the audit lists them
as not sent, and the evaluator counts the run as not valid.

## Line witness

For a cell whose replay flips, the witness specification names the line or branch of the fixed revision that refuses the
replay, and how many times the plan must reach it, with the argument for that number. The cell is then run once more with
the line counter of the language switched on from outside the host application (V8 coverage for Node.js, the `trace`
module for Python, the `Coverage` library for Ruby). The cell is `WITNESSED` when the outcomes are as specified and the
count is the one stated in advance.

## What a result does and does not say

A confirmed `FLIPS` cell says: under this plan and this configuration, the copied credential was accepted at the earlier
revision and refused at the later one, in every run, with all controls holding. A confirmed `ACCEPTED_AT_BOTH` cell says
that the repair did not change this contract; whether that behaviour is wanted is a question about the design of the
software, not something a replay can decide. Nothing here measures how often such behaviour occurs in software at large.
