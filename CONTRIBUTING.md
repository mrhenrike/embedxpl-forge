# Contribution Guidelines

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

## Scope

For this repository:

- In scope: routers, switches, taps, fw and ngfw.
- Out of scope: camera, printer and dvr modules.

## How to Contribute

- Report bugs through repository issues with reproducible evidence.
- Propose improvements in scanners, creds, exploits, protocol clients, and coverage tooling.
- Submit focused pull requests with clear risk and impact notes.

## Bug Reports

Provide:

- exact module path and command sequence
- target profile (vendor/model/firmware when known)
- expected behavior vs actual behavior
- traceback/log evidence with sensitive data removed

## Validation Expectations

Before opening a PR:

1. Run compatibility smoke flow.
2. Run market-priority minimum validator.
3. Regenerate coverage matrix and keep docs in sync.

Example commands:

```bash
python tools/compat_smoke.py
python tools/validate_market_priority_minimums.py
python tools/generate_coverage_matrix.py
```

## Security and Conduct

- Read `SECURITY.md` before reporting vulnerabilities.
- Follow `CODE_OF_CONDUCT.md` for all interactions.
