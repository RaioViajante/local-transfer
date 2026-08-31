# Desktop application

## UX goals

The desktop application should make local transfers understandable without requiring networking knowledge. Its visual design should be restrained, familiar on macOS, Windows, and Linux, and macOS-inspired in clarity rather than an imitation of Apple interfaces.

The primary concepts are:

- nearby devices, with trust state clearly distinguished;
- trusted devices and trust management;
- file selection and drag-and-drop sending;
- explicit incoming transfer requests;
- progress, completion, failure, and cancellation;
- recent transfers with a deliberate retention policy;
- local device identity and settings.

Tray presence, background receiving, and launch-at-login behavior belong to a later phase because they introduce operating-system lifecycle and permission concerns.

## Intended technology

The application will use Tauri 2 for the native shell and command boundary. The frontend will use React and TypeScript, built with Vite and managed with pnpm. Tauri initialization and dependency selection will occur only when the desktop integration phase begins.

The frontend is responsible for presentation, accessibility, navigation, local interaction state, and rendering core events. Rust is responsible for identity, discovery, trust, protocol state, security checks, file access, streaming, persistence, and authoritative transfer state.

## Core integration

Thin Tauri commands should translate frontend intent into typed operations on `local-transfer-core`. A small event bridge should translate core events into serializable frontend events. The bridge should be explicit about operation identifiers and terminal states so stale or duplicated UI events cannot cause unsafe actions.

```text
React UI <-> typed Tauri command/event boundary <-> local-transfer-core
```

The frontend must not duplicate pairing validation, certificate checks, filename safety, overwrite decisions, or transfer state machines. UI validation can improve feedback, but Rust validation remains authoritative. File paths should enter the core only after an explicit picker or drag-and-drop action and should not be reconstructed from untrusted remote filenames.

Shared core capabilities do not mean the GUI must mirror CLI syntax. Both interfaces should be able to discover, pair, inspect trust, send, receive, cancel, and inspect status through workflows appropriate to their environments.

## Initial information architecture

An early desktop flow can remain small:

1. A main view lists nearby devices and distinguishes trusted peers from unpaired devices.
2. Selecting an unpaired device begins pairing; selecting a trusted device exposes file sending.
3. Dragging files onto an eligible trusted device prepares a transfer and requires a clear final action.
4. Incoming requests appear prominently with peer identity, sanitized filename, size, destination, and accept/reject controls.
5. Active transfers show progress and cancellation. Completed or failed transfers show a concise terminal result.
6. Settings expose the local device name/identity, trusted-peer management, destination behavior, and privacy controls.

Recent transfers should be useful without becoming an indefinite record of sensitive filenames. Retention, clearing, and whether history is persisted at all for the first release remain open decisions.

## Platform and accessibility expectations

The application should use native file dialogs and appropriate OS conventions where Tauri supports them. Keyboard navigation, screen-reader labels, visible focus, sufficient contrast, reduced-motion preferences, and progress announcements are requirements rather than later polish.

Platform testing must cover file naming, permissions, drag-and-drop path delivery, application suspension, firewall prompts, multiple windows or instances, and behavior when a transfer outlives the main window. Closing the window should not silently imply background operation before that feature is deliberately implemented.

## Desktop-specific open decisions

- Single-window navigation and the placement of trusted-peer management.
- Default receive destination and per-transfer destination selection.
- History retention and privacy controls.
- Behavior when the window closes during an active transfer.
- Packaging, signing, updates, and platform firewall guidance.
- Concurrent operation with the CLI before a daemon exists.
- Event bridge shape and recovery after frontend reloads.
