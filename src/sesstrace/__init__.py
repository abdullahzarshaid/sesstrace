"""SessTrace: lifecycle test contracts for session termination, withdrawal and expiration.

Two parts share one trace recorder and one verdict rule:

  sesstrace.lab      a self-contained laboratory of eight mechanisms (M1 to M8),
                     each in a vulnerable and a fixed variant, over loopback HTTP
  sesstrace.replay   the same contracts driven against software that was not
                     written for them, from a specification fixed before the run
"""
__version__ = "3.1.1"
