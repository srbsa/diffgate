# DiffGate & SOC 2

> This is a control mapping to help you produce audit evidence. It is not a legal
> attestation and does not make your organization SOC 2 compliant on its own.

SOC 2's change-management criterion, **CC8.1**, requires that changes are *authorized,
designed, tested, and approved before deployment*. DiffGate's orange gate is exactly that
control, mechanized: a high-impact change cannot merge until it is reviewed (and, with a
`testCommand`, until tests pass). Every review run is reproducible, deterministic audit
evidence.

## Why this matters for adoption

Cloud-only AI reviewers are a procurement problem for regulated teams: most lack public
SOC 2 Type II attestation, and sending source to a third party is itself a control
question (CC6.7 — restrict movement of sensitive data). DiffGate's deterministic core runs
**offline, in your CI, with no data egress** — so it's adoptable by teams that can't use a
hosted reviewer at all.

## Rule → control mapping

Generated from [`src/compliance.ts`](src/compliance.ts). Produce evidence for a change:

```bash
diffgate report --compliance            # human-readable control evidence for the diff
diffgate report --compliance --json     # machine-readable, for attaching to an audit
```

| DiffGate rule | SOC 2 control(s) |
|---|---|
| `hardcoded-secret` | CC6.1 (logical access), CC6.7 (data movement) |
| `auth-crypto` | CC6.1 |
| `sql-injection`, `nosql-injection`, `xss-sink`, `path-traversal`, `prototype-pollution` | CC6.6 (boundary), CC7.1 (vuln detection) |
| `permissive-cors` | CC6.6 |
| `dangerous-exec` | CC6.8 (malicious software), CC7.1 |
| `dependency-manifest` | CC6.8, CC7.1 |
| `db-schema-destructive` | CC8.1 (change mgmt), CC7.1 |
| `db-schema-change`, `migration-file`, `public-api-change`, `signature-drift`, `deprecated-api` | CC8.1 |

Controls referenced:

- **CC6.1** — restrict logical access to data and systems
- **CC6.6** — protect against threats from outside the system boundary
- **CC6.7** — restrict the transmission / movement of sensitive data
- **CC6.8** — prevent or detect unauthorized / malicious software
- **CC7.1** — detect and monitor for vulnerabilities and misconfigurations
- **CC8.1** — changes are authorized, designed, tested, and approved before deployment

The mapping is data, not magic — extend `RULE_CONTROLS` in `src/compliance.ts` to cover
custom rules or other frameworks (ISO 27001, PCI DSS).
