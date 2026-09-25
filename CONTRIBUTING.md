# Contributing to subssl

Thanks for helping improve subssl. Small, focused contributions are easiest to
review and ship.

## Before opening an issue

Search existing issues first. For bugs, include the subssl version, installation
method, expected result, actual result, and safe-to-share logs. Never post NIC.RU
credentials, refresh tokens, internal hostnames, private addresses, scan reports,
or full configuration files.

## Development setup

```bash
git clone https://github.com/Dpsley/subssl.git
cd subssl
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
python -m unittest discover -s tests -v
```

The project supports Python 3.10 through 3.12. Keep changes compatible with that
range.

## Pull requests

- Explain the problem and solution in plain language.
- Keep the pull request narrow; separate refactors from behavioural changes.
- Add or update tests for changed behaviour.
- Update the README or changelog when users need to change how they install or
  operate the tool.
- Verify that no generated reports, build output, credentials, or network data
  are included in the diff.

## Code style

Follow the existing code style: type annotations where practical, clear names,
small functions, and user-facing errors that explain the next action. Standard
library `unittest` is used for the test suite.
