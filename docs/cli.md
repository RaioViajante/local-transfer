# Command-line interface

## Purpose

The CLI provides scriptable and terminal-friendly access to the same capabilities as the desktop application. It is an adapter over `local-transfer-core`, not a separate implementation. Commands shown here describe intended workflows and are not yet a compatibility promise.

## Command philosophy

- Prefer clear nouns and verbs over compact but obscure flags.
- Make interactive consent explicit and provide non-interactive behavior only when it is safe and unambiguous.
- Keep human output readable while designing a stable machine-readable mode for automation.
- Send results to standard output, diagnostics to standard error, and return meaningful exit codes.
- Do not expose secrets in arguments, output, process listings, shell history, or logs.
- Use stable peer identifiers when names are ambiguous; display names are conveniences, not identities.
- Surface the same core states and security decisions as the desktop application.

## Conceptual commands

```text
local-transfer devices
local-transfer discover
local-transfer pair <device>
local-transfer peers
local-transfer send file.zip <device>
local-transfer send file1 file2 <device>
local-transfer receive
local-transfer status
```

The likely intent is:

- `devices`: summarize currently visible devices and their trust state.
- `discover`: actively observe nearby discovery events, potentially until interrupted.
- `pair <device>`: initiate the user-verified pairing flow.
- `peers`: list and eventually manage trusted devices.
- `send <path>... <device>`: request transfer of one or more selected paths.
- `receive`: wait for and interactively accept or reject incoming requests.
- `status`: show active transfers and relevant local service state.

The distinction between `devices` and `discover`, the syntax separating multiple paths from the destination, and whether peer removal is a subcommand require usability testing. The first implementation should support a single file before committing to multi-file syntax.

## Interaction behavior

Pairing should show enough authenticated context for the user to verify the other device and should require confirmation. Incoming transfers should show the trusted peer, sanitized proposed filename, declared size, and destination policy before acceptance. Non-interactive acceptance must not become an accidental “accept from anyone” switch.

Long-running commands should respond predictably to terminal interruption. Progress should adapt to interactive terminals and degrade to concise event output when redirected. Cancellation must reach the core rather than only terminating display output.

Device arguments may initially accept an unambiguous name or a displayed short identifier. Ambiguity should produce a useful error and candidate list, never an arbitrary selection.

## Automation

A future structured-output option should use a documented schema and avoid mixing progress rendering with result records. Flags for confirmation, destination selection, timeouts, or overwrite policy should have conservative defaults. Automation behavior and exit-code categories should be designed before declaring the CLI stable.

The MVP does not assume a background daemon. Commands that need discovery or receiving may remain running and host the core in their own process. If `local-transferd` is introduced later, CLI commands may become clients of its local authenticated IPC API without changing the user-facing security model.

## Errors and privacy

Errors should be actionable while avoiding disclosure of secrets or unnecessary absolute paths. Expected categories include invalid arguments, ambiguous device, untrusted peer, pairing failure, rejection, cancellation, network failure, filesystem failure, incompatible protocol, and unavailable local service.

The CLI must not emit telemetry or analytics. Verbose logging should be opt-in and must redact keys, pairing material, file content, and other sensitive protocol values.
