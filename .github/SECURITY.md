# Security Policy

## Reporting a vulnerability

Please report security issues privately, through
[GitHub's private vulnerability reporting](https://github.com/MatteoMinati/LuxCipher/security/advisories/new),
rather than as a public issue.

## Scope and expectations

LuxCipher is a personal project, not an audited product. It has not been
reviewed by anyone outside its author, and it is published as a portfolio and
learning piece. Treat it accordingly before trusting real passwords to it.

The design rules, the decisions behind them, and an explicit list of what
LuxCipher does and does not defend against are in
[docs/SECURITY.md](../docs/SECURITY.md). Anything already recorded there as a
known limitation, such as the absence of code signing or the inability to wipe
the derived key from Python memory, is a known gap rather than a new finding.

## Supported versions

Only the latest release is supported.
