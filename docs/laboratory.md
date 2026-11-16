# The synthetic laboratory

The laboratory is a small OAuth 2.0 and OpenID Connect deployment on loopback: an identity provider, two relying parties
and a resource server, all in the standard library. One flag per mechanism switches the vulnerable behaviour on;
everything else is the same in both variants. It exists to demonstrate each mechanism in isolation and to exercise the
recorder and the verdict rule on a system whose behaviour is known.

It is not a scanner, not a conformance suite, not a collection of reproduced CVEs and not a model of any product.

```bash
sesstrace lab run --out results/      # twelve withdrawal scenarios and four expiration scenarios
sesstrace lab verify                  # the same, compared with the reference output in the package
```

## Mechanisms

| ID | Demonstration | Boundary that must not be generalised |
|---|---|---|
| M1 | A copied relying-party session cookie is replayed after local logout | Local logout need not end other clients or independent grants |
| M2 | An access token is replayed after federated logout | Revoking tokens at logout is a policy of this laboratory, not an unconditional requirement of OpenID Connect |
| M3 | A refresh token is used after its revocation was acknowledged | The status of a revocation response alone does not show which effects occurred |
| M4 | A cookie of the second relying party is replayed after a delivered back-channel logout | The receiver here is not a standards-conformant implementation |
| M5 | A cached introspection result is accepted after revocation | RFC 7662 allows caching as a trade-off; immediate withdrawal is a policy of this laboratory |
| M6 | Another session keeps working after a password change | Ending other sessions on a password change is a policy, not a universal requirement |
| M7 | A token is used after its idle lifetime has passed | A policy fixture with a manual clock |
| M8 | A token is used after its absolute lifetime has passed | A policy fixture with a manual clock |

M1 to M6 run against the four servers and are recorded by the trace recorder. M7 and M8 are separate fixtures with a clock
that the scenario advances by hand, so that the lifetime boundary is hit exactly and nothing sleeps.

## Outcomes

For each mechanism and variant the runner follows one lifecycle: set-up, first use, the termination event, replay of the
earlier artifact, and three controls (the artifact worked before the event; a fresh login works after it; an unrelated
user is not affected).

- `FAIL`: a valid first use and a termination that reported success, followed by a replay that completed the protected
  operation.
- `PASS`: the same, followed by the endpoint's own denial.
- `INCONCLUSIVE`: a failed precondition, an unexpected or malformed answer, an answer for another user, a transport
  failure, or a token that was minted but could not be used. This never counts for either side.

A status code alone does not establish success. A profile or resource answer must name the expected user and data; a
refresh must mint a token that then reaches the protected resource; a denial must be the endpoint's specific error.

The expected pattern is `FAIL` on every vulnerable variant, `PASS` on every fixed one, and no failing control. `lab run`
exits with 0 only then.

## Reference output

Identifiers come from a seeded generator, and the traces hold no clock readings, ports or credential values. A run
therefore writes the same twelve trace files on every machine. The package keeps them in `src/sesstrace/lab/reference/`,
together with the result of the expiration fixtures, and `sesstrace lab verify` compares a fresh run with them byte for
byte. The reference files are the output archived with the manuscript.

The seeded generator is deliberate: this is a laboratory, and reproducible identifiers matter more here than
unpredictable ones.
