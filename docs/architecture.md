# Architecture

## Goals

`local-transfer` must serve normal desktop users and command-line users without maintaining two implementations of identity, discovery, pairing, security, or transfer behavior. The architecture therefore treats the Rust core as the product's source of domain behavior and treats the CLI and desktop application as adapters.

The design also aims to remain portable across macOS, Windows, and Linux, operate without an external service, stream large files with bounded memory use, and leave room for background operation without making a daemon an MVP prerequisite.

## Planned repository layout

```text
local-transfer/
├── crates/
│   └── local-transfer-core/
├── apps/
│   ├── cli/
│   └── desktop/
└── docs/
```

This is a target layout, not a commitment to create every directory during the documentation phase.

## Components

### Core

`local-transfer-core` will be a platform-independent Rust library responsible for:

- device identity and local identity persistence;
- peer discovery abstractions and discovered-device state;
- pairing and trusted-peer records;
- connection authentication and security policy;
- transfer negotiation and protocol state;
- streaming file input and output;
- progress, cancellation, and error reporting;
- persistent settings and transfer metadata where appropriate.

Platform-specific behavior should sit behind narrow interfaces. The core may depend on portable libraries and explicit platform adapters, but it must not depend on either user interface. Keeping domain state transitions in one place prevents security and behavioral differences between the CLI and desktop application.

The trusted-peer model and the pairing state machine are security-sensitive core responsibilities. [trust.md](trust.md) specifies what belongs to the core, what the transport/crypto adapter provides, and what the UI and persistence adapters own.

### Local device identifier

The installation identifier is a canonical UUID version 4 generated from operating-system randomness. The core stores it as `device-id` in the platform application configuration directory and also accepts an explicit storage path for isolated tests and future host adapters. Initial creation uses a fully written temporary file and a no-clobber persist operation so concurrent initialization cannot replace an established identity. Existing unreadable or invalid data is an error and is never silently regenerated.

`DeviceId` is the stable installation identity. `DeviceName` is a separate mutable presentation label, stored as `device-name` in the same configuration directory. A missing name is initialized to `Local Device`; invalid existing name data is reported rather than reset. Name updates atomically replace only the display-name file and never modify the device identifier.

`Platform` is separate bounded descriptive metadata derived only from Rust's compilation target. It reports `macos`, `windows`, or `linux`; unsupported targets produce an explicit error. It contains no version, distribution, architecture, user, network, or hardware information and is never an identity or trust input.

CLI and desktop adapters consume this state through the synchronous local-device public API. That API returns an immutable `LocalDevice` snapshot and coordinates loading and display-name updates through `LocalDeviceManager`; it owns configuration-directory selection and keeps filesystem stores, paths, atomic publication, and permission handling private. The dependency direction is therefore adapters → local-device API → `DeviceId` / `DeviceName` / `Platform` → private persistence.

### CLI

The CLI will be a Rust binary using Clap for argument parsing. It will call `local-transfer-core` directly and translate core events and errors into terminal output and exit codes. It should contain presentation and process-lifecycle concerns, not a second protocol implementation.

### Desktop

The desktop application will use Tauri 2 as its native application boundary and React, TypeScript, Vite, and pnpm for its webview UI. Thin Tauri commands will invoke the Rust core. Core events will be converted into stable, serializable desktop-facing messages for discovery changes, pairing prompts, incoming requests, progress, cancellation, and completion.

The frontend must not own trust decisions, construct wire-protocol messages, or access files beyond paths explicitly authorized through the desktop workflow. This keeps security-sensitive work in Rust and makes the frontend replaceable.

## Dependency direction

```text
CLI presentation ────────┐
                         ├──> local-transfer-core ──> portable libraries / platform adapters
Desktop UI -> Tauri glue ┘
```

Dependencies point inward toward the core. The core has no dependency on Clap, Tauri, React, or desktop presentation types. Shared capability means both interfaces use the same core operations; it does not require their workflows or output formats to be identical.

## Data flow

A typical transfer is expected to follow this flow:

1. A discovery adapter reports a minimal peer advertisement to the core.
2. The core exposes a discovered-device event to the active interface.
3. The user initiates or responds to pairing; the core verifies the pairing exchange and persists the resulting trust record.
4. The sender selects files and a trusted destination. The interface passes authorized paths and intent to the core.
5. The core establishes an authenticated connection, negotiates a transfer request, and reports it to the receiver.
6. After explicit acceptance, the core reads and writes bounded chunks while emitting progress and observing cancellation.
7. The core verifies completion, safely finalizes destination files, and records only the metadata required by the product.

The exact asynchronous API, event transport, and persistence format remain implementation decisions. The important boundary is that both interfaces observe the same domain operations and state transitions.

## Process model and future daemon

For the MVP, the CLI and desktop application should host the core in their own processes. This avoids an installer-managed background service, inter-process authentication, lifecycle coordination, and another protocol boundary before continuous availability is required.

A future `local-transferd` may host discovery, trusted-peer state, and transfers when background receiving or tray operation justifies it. If introduced, it should wrap the same core and expose a local, authenticated IPC API to clients. The core must not assume that a daemon exists, and no daemon is part of the initial architecture unless testing shows that operating-system lifecycle constraints make it necessary.

Running the CLI and desktop application simultaneously may create discovery port, identity-store, or transfer-listener conflicts. MVP policy for concurrent instances must be decided before both interfaces become functional.

## Architectural constraints

- Network peers and the local UI are separate trust boundaries.
- File content is streamed rather than buffered as a complete object.
- Cancellation and progress are core concepts, not UI-only behavior.
- Persistence is minimal and must not expose transfer history through discovery.
- Protocol types should be versioned and bounded, but their encoding is not selected yet.
- Testable interfaces should separate network, filesystem, clock, and persistence effects from state transitions.
