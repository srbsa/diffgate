# Security Policy

DiffGate is a deterministic security gate, so we hold its own code to the same bar. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's [**Report a vulnerability**](https://github.com/srbsa/diffgate/security/advisories/new) flow (the repo's **Security → Advisories** tab). This keeps the report confidential until a fix is available and lets us coordinate a disclosure with you.

When you report, please include:

- the affected version (`diffgate --version`) and surface (CLI, MCP server, or VS Code / Open VSX extension);
- a minimal reproduction — ideally a small diff or file that triggers the issue;
- the impact you observed (e.g. a false *clear* on a real sink, a crash, or code execution).

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity rating within 7 business days.
- A fix or mitigation plan for confirmed issues, and credit in the release notes if you'd like it.

## Scope

In scope: the published npm package (`diffgate-review`), the VS Code / Open VSX extension, and the MCP server.

Of particular interest:

- a **false clear** — a real injection sink the engine reports as safe (a missed detection in a covered tier);
- a way to make the gate **block-bypass** or crash on crafted input;
- any code-execution, path-traversal, or secret-exposure issue in DiffGate itself.

Out of scope: findings in *your* code that DiffGate correctly flags, and coverage gaps already documented as "not yet covered" in [docs/SCOPE.md](docs/SCOPE.md) (those are feature requests — open a regular issue).

## Supported versions

Security fixes land on the latest published release. Please upgrade to the most recent version before reporting.
