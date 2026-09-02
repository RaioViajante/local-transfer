# Claude Repository Guide

Before making changes, read [AGENTS.md](AGENTS.md) and treat it as the canonical repository policy. Then read the complete issue, the relevant implementation and tests, and any linked project documentation.

Plan internally before editing. Infer from established repository conventions unless a genuinely unresolved product decision blocks the task; ask only in that case. Do not silently broaden the issue, replace established architecture without strong task-driven justification, or introduce speculative work. Prefer focused edits and preserve all user changes.

Run targeted tests continuously while developing. Before completion, run the complete validation suite from `AGENTS.md`, then review `git diff`, `git diff --check`, and `git status`. Report exactly what changed and every validation command that ran. Never claim success when a required check was skipped or failed.

When the task delivers a GitHub issue, that issue is not fully completed until the approved implementation is pushed to `origin/main`, `HEAD` matches `origin/main`, and the corresponding GitHub issue has been closed. Follow the [Issue completion](AGENTS.md#issue-completion) rules: use `gh` when available, confirm the mapping with `gh issue list` / `gh issue view`, close only the unambiguously matching issue, never guess an ambiguous issue number, never close related or dependent issues automatically, and never close an issue whose acceptance criteria are not actually satisfied.

Never perform destructive Git operations. Do not commit or push unless the task explicitly requests it.
