# Roadmap

The phases below are incremental capability boundaries, not release dates. Each phase should preserve cross-platform behavior and keep security-relevant logic in `local-transfer-core`. Later phases may feed small design changes back into earlier foundations.

## Phase 0: Architecture and foundation

- Agree on the threat model, dependency direction, terminology, and protocol invariants.
- Choose workspace conventions, supported Rust/toolchain policy, licensing, and contribution process.
- Define core boundaries and test strategy without initializing Tauri or implementing networking prematurely.
- Record key design decisions and explicit security review gates.

Exit condition: the repository can accept a minimal Rust workspace without unresolved structural ambiguity.

## Phase 1: Device identity

- Define stable device identity and user-visible naming.
- Evaluate maintained key types and OS-appropriate private-key storage.
- Implement identity creation, loading, reset behavior, and testable persistence boundaries.
- Specify how identity changes appear to previously paired peers.

Exit condition: the core can safely persist and reload a local identity on all target platforms.

## Phase 2: LAN discovery

- Evaluate cross-platform mDNS/DNS-SD libraries and platform behavior.
- Advertise and browse `_local-transfer._tcp` with minimal metadata.
- Model appearance, updates, expiry, duplicate names, and changing addresses.
- Bound and validate discovery inputs.

Exit condition: two instances can locate one another on representative macOS, Windows, and Linux networks without treating discovery as authentication.

## Phase 3: Pairing

The trusted-peer and pairing-lifecycle specification is [trust.md](trust.md); this phase implements it.

- Select and document an established pairing construction and verification UX.
- Implement explicit accept, reject, timeout, retry limits, persistence, and revocation.
- Bind stable peer identity to authenticated public-key material.
- Test active interception, identity mismatch, malformed input, and interrupted pairing.

Exit condition: users can establish and revoke a trust relationship with a reviewed security rationale.

## Phase 4: Basic file transfer

- Transfer one regular file over a direct LAN connection.
- Negotiate a request and require receiver accept or reject.
- Stream with bounded memory, backpressure, progress, cancellation, and safe incomplete-file cleanup.
- Apply cross-platform filename, destination, collision, and size policies.

Exit condition: a large single file can be transferred reliably between supported platforms without full-file buffering or unsafe path handling.

## Phase 5: Security and TLS hardening

- Use maintained TLS support and bind the connection to paired peer keys through pinning or an established equivalent.
- Define protocol bounds, timeouts, replay considerations, rate controls, and failure behavior.
- Review key storage, logs, temporary files, metadata privacy, and resource-exhaustion cases.
- Add adversarial tests and obtain focused external review when feasible.

Some transport security may be required earlier to avoid building an unsafe transfer path. This phase marks completion of the hardening and review needed before recommending real-world use, not permission to defer essential authentication.

Exit condition: transport and peer authentication have a documented, tested security design with known residual risks.

## Phase 6: CLI refinement

- Stabilize command names, peer selection, prompts, progress, cancellation, and exit codes.
- Add a documented structured-output mode for automation.
- Make receive and interruption behavior predictable without a daemon.
- Verify that CLI capabilities map directly to core operations.

Exit condition: the CLI is usable interactively and scriptably with conservative defaults.

## Phase 7: Desktop integration

- Initialize Tauri 2 with React, TypeScript, Vite, and pnpm.
- Build a thin typed command/event bridge to the Rust core.
- Implement nearby/trusted device views, pairing, drag-and-drop sending, incoming requests, progress, cancellation, settings, and accessible error states.
- Validate lifecycle and filesystem behavior on all target platforms.

Exit condition: the desktop application exposes the established core capabilities without duplicating security or protocol logic.

## Phase 8: Background and tray operation

- Evaluate tray behavior, launch-at-login, notifications, and platform lifecycle constraints.
- Decide whether a `local-transferd` process is justified.
- If needed, design authenticated local IPC, ownership, upgrades, crash recovery, and CLI/desktop coordination.

Exit condition: receiving can continue with clear user control and without ambiguous hidden processes.

## Phase 9: Folders and multiple files

- Extend negotiation to bounded manifests and multiple streamed entries.
- Define directory, symlink, permission, collision, partial-success, and aggregate-progress policies.
- Prevent traversal and link attacks across complete directory trees.

Exit condition: batches and folders transfer safely with understandable acceptance and failure semantics.

## Phase 10: Clipboard and text sharing

- Define explicit text payload types, bounds, previews, consent, and history behavior.
- Treat received text as untrusted and avoid automatic execution or unsafe rich-content rendering.
- Integrate platform clipboard access with visible user control.

Exit condition: paired users can share bounded text without weakening the file-transfer trust model.

## Cross-cutting work

Every phase includes documentation, cross-platform tests, accessibility where user-facing, privacy review, compatibility considerations, and updates to unresolved decisions. Internet relay, accounts, cloud storage, telemetry, and analytics are not implied by this roadmap.
