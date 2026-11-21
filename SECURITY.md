# Security

## Reporting a problem in SessTrace

Report a suspected vulnerability in SessTrace itself privately, through the Security tab of the repository
(<https://github.com/abdullahzarshaid/sesstrace/security>). Please do not open a public issue for it.

The supported version is 3.1.1.

## Using SessTrace safely

- The laboratory and the tests use loopback addresses only.
- `sesstrace run` sends requests to the address given with `--base`. Point it only at software that you own or are
  allowed to test.
- The checks in `checks/` download and start third-party software at old, vulnerable revisions. Run them only in a
  disposable, unprivileged local container or virtual machine, never on a production server and never with real
  credentials.
- Traces do not contain credential values. They do contain the addresses, paths and status codes of the requests that
  were sent, so read a trace before you share it.

## Findings about other software

The records in `checks/records/` describe old releases of public projects whose repairs were already published. A new
finding about current software belongs with the maintainers of that software first.
