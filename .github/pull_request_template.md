## Description

<!-- Provide a concise summary of the changes introduced by this pull request. -->

## Type of Change

- [ ] `feat`: New feature or capability
- [ ] `fix`: Bug fix
- [ ] `test`: New or updated tests / verification gates
- [ ] `docs`: Documentation updates
- [ ] `build` / `ci`: Build system, packaging, or CI workflow changes

## Verification Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy` passes (strict)
- [ ] `pytest` passes, including the negative cases (every one fails closed)
- [ ] `python tools/lint_pins.py` passes
- [ ] `pre-commit run --all-files` passes
- [ ] No secrets, keys, hostnames, addresses or planning identifiers in tracked files
