"""The synthetic laboratory.

  servers     identity provider, two relying parties and a resource server,
              with one documented flag per mechanism (vulnerable or fixed)
  mechanisms  M1 to M6: set-up of the artifact, the protected operation and
              the termination event
  runner      runs every mechanism in both variants and writes the results
  expiry      M7 and M8: idle and absolute lifetime, on a manual clock
  verify      compares a fresh run with the reference output kept in the package
"""
