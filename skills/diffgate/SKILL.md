---
description: Review the current diff with DiffGate — a deterministic gate that grades each changed line green/yellow/orange by impact and catches deleted guardrails. Use when the user asks to review, triage, check, or gate their current changes before committing or opening a PR.
---

Call the `diffgate_check_staged` MCP tool to triage the current diff (mode: "staged" if the user says they've staged their changes, otherwise "working"). Summarize the result by tier — 🟠 orange (fix before shipping), 🟡 yellow (worth a look), 🟢 green (informational) — citing file:line for each orange/yellow finding. If there are no findings, say so plainly rather than padding the summary.
