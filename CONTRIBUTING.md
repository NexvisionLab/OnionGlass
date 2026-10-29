# Contributing

Thank you for your interest. The project is pre-alpha and its design is still being set, so please open an issue and talk to us before writing a large change.

## Licence of contributions

By contributing you agree your work is licensed under the project's licence, GNU Affero General Public License version 3 (`AGPL-3.0-only`). Every source file starts with an SPDX line saying so.

A contributor agreement or sign-off requirement is still to be decided and will be in place before outside contributions are merged. Until then, expect that pull requests from outside the maintainers will wait for it.

## Rules that are not negotiable

1. **No illegal or harmful content in the repository.** Tests use benign onion sites such as the Tor Project, DuckDuckGo, Debian and similar, plus synthetic hostile input such as script injection samples. Never add a capture, screenshot, address list or fixture taken from a site that hosts illegal material.
2. **No secrets, hostnames or addresses that belong to a real deployment.** Use documentation-reserved names and addresses in examples.
3. **No weakening of a security property to make a test or feature easier.** The properties are listed in [docs/threat-model.md](docs/threat-model.md). A change that touches one needs a test that proves it still holds.
4. **Use your own no-reply identity.** Do not commit with a personal email address you want to keep private.

## Development setup

You need Python 3.11 or newer.

```bash
python -m venv .venv
. .venv/bin/activate          # on Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Checks to run before opening a pull request

```bash
ruff check .
ruff format --check .
mypy
pytest
```

All of these also run in continuous integration, along with secret scanning, CodeQL and a dependency review.

## Code style

- Type annotations everywhere. `mypy` runs in strict mode.
- Small modules with one job. The rewriter, policy and evidence modules are security-sensitive and get closer review.
- Fail closed. When a safety check cannot be completed, refuse the request.
- Never log request bodies, passwords, cookies or visitor addresses unless the code path is explicitly about audit and the log policy allows it.

## Commit messages

Short summary line in the imperative mood, then a blank line and a body that explains why, not what. One logical change per commit.

## Reporting security issues

Do not use issues or pull requests. See [SECURITY.md](SECURITY.md).
