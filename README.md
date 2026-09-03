# local-transfer

`local-transfer` is a planned peer-to-peer file transfer tool for macOS, Windows, and Linux. It will provide both a graphical desktop application and a command-line interface backed by the same platform-independent Rust core.

The project exists to make transfers between devices on the same local network straightforward without requiring an account, cloud storage, an external server, telemetry, or analytics. Discovery is not trust: devices must pair explicitly before they can exchange files, and transfers must be encrypted and streamed safely.

## Status

The project has a minimal Rust workspace establishing the shared core and CLI boundaries. No protocol implementation, functional command-line interface, or desktop application exists yet.

## Planned structure

```text
local-transfer/
├── crates/
│   └── local-transfer-core/   # Shared Rust domain and future protocol logic
├── apps/
│   ├── cli/                   # Rust CLI using the core directly
│   └── desktop/               # Tauri 2, React, TypeScript, Vite, and pnpm
└── docs/                      # Design and product documentation
```

## Principles

- Local network first; no account, cloud dependency, or external coordination server.
- Explicit pairing and least-privilege trust boundaries.
- Established cryptographic protocols and libraries only.
- Streaming transfers with progress, cancellation, and bounded memory use.
- Safe handling of filenames and destination paths.
- Equivalent underlying capabilities in the desktop and CLI interfaces.

## Documentation

- [Architecture](docs/architecture.md)
- [Security](docs/security.md)
- [Trust and pairing](docs/trust.md)
- [Protocol](docs/protocol.md)
- [CLI](docs/cli.md)
- [Desktop](docs/desktop.md)
- [Roadmap](docs/roadmap.md)

## Contributing

The design is intentionally unsettled in several areas. Before implementation, proposals should preserve the dependency direction, threat model, and cross-platform requirements described in the documentation. Contribution guidance and licensing will be added before accepting code contributions.
