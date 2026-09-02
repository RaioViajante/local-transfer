# AI Agent Engineering Guide

This file is the canonical, tool-agnostic policy for AI coding agents in this repository. Read the task, this file, and the relevant project documentation before changing files. All source code, comments, documentation, issues, commit messages, branch names, and pull requests must be in English.

## Project principles

- Keep the product local-first: no accounts, cloud dependency, external coordination service, telemetry, or analytics.
- Treat the local network as untrusted. Discovery is advisory and never establishes identity, trust, or authorization.
- Preserve privacy through minimal, non-sensitive network metadata and minimal local persistence.
- Keep behavior predictable across macOS, Windows, and Linux, with explicit platform differences and failure modes.
- Prefer idiomatic, maintainable Rust and clear ownership over cleverness.
- Reuse the standard library and existing dependencies where practical; keep resource use and dependency growth bounded.

The threat model and unresolved design decisions in [README.md](README.md), [docs/architecture.md](docs/architecture.md), [docs/security.md](docs/security.md), and [docs/protocol.md](docs/protocol.md) are authoritative. Do not turn planned behavior into an implementation convention prematurely.

## Repository architecture

This is a Rust 2024 workspace with Rust 1.85 as its minimum supported version.

- `crates/local-transfer-core`: shared domain library. It owns local device identity, display-name and platform models, private filesystem persistence, bounded discovery metadata, DNS-SD advertisement, and DNS-SD browsing. Public modules expose small typed APIs; infrastructure adapters and persistence details remain private.
- `apps/cli`: Clap-based `local-transfer` binary and terminal adapter. It currently exposes the `device` command and translates core results into stdout, stderr, and exit codes. Domain behavior belongs in the core rather than the CLI.
- `apps/desktop`: reserved for the future Tauri/React application; it is not currently a workspace member or an initialized application. Follow its README and `docs/desktop.md` without creating planned components unless the task requires them.
- `docs`: architecture, security, protocol, CLI, desktop, and roadmap decisions. Cross-reference these documents instead of duplicating them.

Dependencies point from applications toward `local-transfer-core`; the core must not depend on UI frameworks or presentation types. Current APIs are synchronous, with nonblocking polling for discovery events. Network and lifecycle effects are hidden behind narrow internal backends so state transitions can be tested deterministically.

## Development workflow

For every task:

1. Read the issue or task completely.
2. Check `git status`, then inspect the related implementation and documentation before editing.
3. Identify existing abstractions, public boundaries, error types, and tests.
4. Make the smallest coherent change that satisfies the task.
5. Avoid unrelated refactors, cleanup, or dependency updates.
6. Add or update tests for changed behavior.
7. Update documentation only when behavior, public interfaces, security assumptions, or documented decisions change.
8. Run targeted checks while developing, then the complete validation suite.
9. Review `git diff`, `git diff --check`, and `git status` for scope, correctness, and accidental changes.
10. Commit or push only when explicitly requested and only after validation passes.
11. When the task delivers a GitHub issue, close that issue as the final delivery step once every condition in [Issue completion](#issue-completion) is met.

## Required validation

Run all of these from the repository root before considering a task complete:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Do not claim success when a required command was skipped or failed. If an environment limitation prevents validation, report the exact limitation and command.

## Issue completion

A GitHub issue is not fully completed until all of the following are true:

1. The implementation is complete.
2. Required validation passes.
3. The implementation has been reviewed and approved.
4. The approved commit has been pushed to `origin/main`.
5. `HEAD` matches `origin/main`.
6. The corresponding GitHub issue has been closed.

Closing the issue is the final delivery step. When closing an issue:

- Use the GitHub CLI (`gh`) when it is available.
- Confirm the mapping with `gh issue list` and `gh issue view` first, and close only the issue that corresponds to the implemented task.
- Never guess an issue number when the mapping is ambiguous.
- Do not close an issue when its acceptance criteria are not actually satisfied.
- Do not close related or dependent issues automatically.
- Do not close an issue merely because a commit exists.
- When useful, leave a concise closing comment that references the implementation commit.

## Rust standards

- Model meaningful domain failures with focused typed errors. Implement `Display` and `Error`, retain underlying sources where useful, and do not expose infrastructure types merely for convenience.
- Avoid panics in normal runtime paths. Do not use `unwrap()` or `expect()` in production paths unless an invariant makes failure impossible and a nearby explanation makes that invariant clear. Their use in tests is consistent with the current test style.
- Favor ownership and lifetime choices that make APIs and state transitions easy to understand. Avoid premature abstraction or lifetime complexity.
- Treat all network-controlled data as untrusted. Validate structure and compatibility, enforce explicit byte/count bounds, reject invalid required data, and handle optional advisory data conservatively.
- Keep public APIs intentional and minimal. Use private helpers/backends for infrastructure, `#[must_use]` where ignoring a value is likely erroneous, and rustdoc for public contracts and security-relevant semantics.
- Make platform support explicit with `cfg` or narrow platform abstractions. Unsupported targets and platform limitations must fail or be documented explicitly, never silently assume one operating system's behavior.
- Preserve privacy-safe discovery: permanent device IDs, secrets, usernames, machine hostnames, filesystem data, and hardware identifiers do not belong in advertisements. Ephemeral DNS-SD names are not identity.
- Preserve persistence semantics: invalid existing state is an error rather than an invitation to regenerate identity; writes use temporary files and atomic publication/replacement where established; application-owned Unix directories/files retain restrictive permissions. Do not claim equivalent custom Windows ACL hardening where it does not exist.
- Keep CLI presentation separate from domain behavior. Successful results use stdout; diagnostics use stderr with meaningful nonzero exit status.

## Dependencies

Do not add dependencies casually. Before adding one:

- verify that the standard library or current workspace dependencies cannot reasonably solve the problem;
- justify the dependency in the task or change description;
- prefer a mature, maintained crate with an appropriate security and portability posture;
- avoid a large dependency tree for trivial functionality.

Never update unrelated dependencies or lockfile entries during an issue.

## Testing

Behavior changes require tests. Follow the existing style: unit tests live beside the domain or adapter code under `#[cfg(test)]`; filesystem tests use isolated temporary directories; discovery lifecycle/state tests use fake backends rather than relying on a live network.

Prefer deterministic tests, explicit boundary and error cases, and regression tests for bugs. Avoid timing-sensitive or network-flaky tests when injection or a small internal abstraction can make behavior deterministic. Keep platform-specific tests explicitly gated. Test public behavior and security-relevant invariants, not incidental implementation details.

## Scope discipline

Do not perform unrelated refactors, speculative architecture, feature creep, unrelated formatting, unrelated API renames, or rewrites of working code merely because another design is preferred. Do not implement roadmap components or settle documented open decisions unless the task specifically requires it.

## Security and privacy

- Treat service names, TXT data, addresses, ports, filenames, protocol messages, and all other network-derived values as hostile input.
- Validate and bound network-controlled strings, collections, and payloads before retaining or exposing them.
- Do not advertise or persist identifiers and metadata beyond what the documented operation requires. Never turn a transient discovery key into a trust identifier.
- Do not log secrets, pairing material, file contents, unnecessary full paths, or sensitive local information.
- Preserve explicit consent, trust, authentication, filesystem-safety, and privacy boundaries. Never weaken one to simplify implementation or testing.
- Use established cryptographic protocols and maintained libraries only; do not invent cryptographic primitives.

## Git safety and commits

Preserve all user changes, including unexpected uncommitted work. Never autonomously force-push, rewrite published history, run `git reset --hard` or `git clean -fd`, delete branches, discard user changes, or amend unrelated commits.

Use Conventional Commits with an accurate scope when applicable, following repository history, for example:

- `feat(discovery): add ...`
- `fix(core): prevent ...`
- `test(core): cover ...`
- `docs: document ...`
- `refactor(core): simplify ...`
- `chore: update ...`

Subjects must be English, imperative, concise, accurately scoped, and have no trailing period. Do not commit until all required validation passes. Do not commit or push unless explicitly requested.
