---
name: python-standard
description: Python coding standard for owned tooling in cold-chain-monitor-c-rp2350.
---

# Python Standard (cold-chain-monitor-c-rp2350)

Owned Python files under `scripts/` and `test/` and any future tooling must
comply with strict PEP8, a hard eight-line executable function-body limit with
no exceptions, no blank lines inside function bodies, and complete NumPy-style
docstrings.

## Scope

Comply with all Python files in `scripts/` and `test/` and all new Python
tools. Vendored or third-party scripts are excluded.

## Rules

- Use four spaces, no tabs, and `snake_case` names.
- Use `UPPER_SNAKE_CASE` module constants and `PascalCase` classes.
- Keep lines within 79 characters.
- Use standard-library imports before third-party imports.
- Use two blank lines between top-level definitions.
- Every module has a module docstring.
- Every function, including private and nested functions, has a NumPy-style
  docstring with purpose, `Parameters`, and `Returns` sections.
- Every function executable body contains at most eight lines. There are no
  exceptions, including cryptographic algorithms.
- Function bodies contain no blank lines.
- Never log or hard-code credentials or secrets.

## Verification

Run `python3 -m flake8 <file.py>` when flake8 is available. Also run:

```bash
python3 scripts/audit_python_standard.py
```