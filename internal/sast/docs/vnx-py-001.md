---
title: "VNX-PY-001 – Missing Python Lock File"
description: "Detect a Pipfile without Pipfile.lock, and a pyproject.toml managed by Poetry, PDM or uv that declares dependencies but has no lock file, leaving every install to re-resolve version ranges."
---

## Overview

This rule fires when a Python project has a `pyproject.toml` or `Pipfile` but no corresponding lock file (`uv.lock`, `poetry.lock`, or `Pipfile.lock`). Lock files record the exact resolved versions and integrity hashes of every dependency in the tree. Without one, each new install can silently pull a different version of any transitive dependency — including one that has been compromised or typosquatted. This maps to [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html).

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

Without a lock file, floating version ranges such as `requests>=2.28` or `numpy~=1.24` are re-resolved on every fresh install. An attacker who publishes a malicious version of any package in your dependency tree — or who compromises a package maintainer account — can have their code pulled into your production builds without any visible change to your repository. This is the attack class described by MITRE ATT&CK T1195.001 (Supply Chain Compromise: Compromise Software Dependencies) and was demonstrated by real incidents such as the `event-stream` and `PyTorch nightly` supply chain attacks.

Even without a malicious actor, non-deterministic resolution means your CI/CD pipeline may test against one set of dependencies while production runs a different one. Reproducing bugs becomes harder, and security patches applied to a transitive dependency may or may not take effect depending on when a fresh install is triggered.

## What Gets Flagged

The rule fires on a `Pipfile` with no `Pipfile.lock` beside it (reported on its `[packages]` header), and on a `pyproject.toml` that configures a locking dependency manager (`[tool.poetry]`, `[tool.pdm]` or `[tool.uv]`), declares at least one dependency besides `python`, and has no `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock` or `pylock.toml` in its directory. A `uv.lock` in an enclosing directory counts, so uv workspace members are not reported.

Not flagged: a setuptools, flit or hatch `pyproject.toml` with no locking tool configured (a library publishes ranges by design), a project with no dependencies, `requirements.txt`, and test fixtures.

```toml
# FLAGGED: pyproject.toml, no poetry.lock next to it
[tool.poetry]
name = "orders-api"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.110"
```

```
# FLAGGED: Pipfile present, no Pipfile.lock
$ ls
Pipfile   app.py
# (Pipfile.lock is missing)
```

## Remediation

1. **Choose a lock-file-aware tool and generate the lock file.** All three major Python packaging tools support lock files:

```bash
# uv (recommended — fast, hash-verified)
uv lock
uv sync

# Poetry
poetry lock
poetry install

# Pipenv
pipenv lock
pipenv install
```

2. **Commit the lock file to version control.** The lock file must be tracked in source control so every environment — developer laptops, CI runners, production containers — installs exactly the same dependency graph.

```bash
git add uv.lock          # or poetry.lock / Pipfile.lock
git commit -m "chore: add Python lock file"
```

3. **Install from the lock file in CI/CD.** Use commands that refuse to deviate from the recorded versions:

```bash
# uv — strict mode honours the lock file exactly
uv sync --frozen

# pip with hash verification (works with requirements.txt exported from uv/poetry)
pip install -r requirements.txt --require-hashes
```

4. **Audit the lock file regularly.** Lock files freeze versions, but those versions may still receive CVEs over time. Pair lock-file discipline with a dependency scanning tool and re-run `uv lock --upgrade-package <pkg>` or `poetry update` when patches are released.

5. **Never gitignore lock files.** Check that `uv.lock`, `poetry.lock`, and `Pipfile.lock` are not listed in `.gitignore`. These files are intentionally committed even for applications (as opposed to libraries, where policy differs).

```bash
# SAFE: install exactly what the lock file specifies with hash verification
uv sync --frozen
```

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [uv documentation – Lock files](https://docs.astral.sh/uv/concepts/projects/sync/)
- [Poetry documentation – poetry.lock](https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock)
- [Pipenv documentation – Pipfile.lock](https://pipenv.pypa.io/en/latest/pipfile.html)
- [MITRE ATT&CK T1195.001 – Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [CAPEC-185: Malicious Software Download](https://capec.mitre.org/data/definitions/185.html)
