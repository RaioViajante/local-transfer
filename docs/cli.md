# Command-line interface

## Purpose

The CLI provides scriptable and terminal-friendly access to the same capabilities as the desktop application. It is an adapter over `local-transfer-core`, not a separate implementation. Commands shown here describe intended workflows and are not yet a compatibility promise.

## Local device inspection

```text
local-transfer device
```

The `device` command loads the current installation through the public core API and prints its permanent device ID, editable display name, and platform. Successful output goes to standard output; load failures and argument errors go to standard error with a non-zero exit status.

## Nearby device discovery

```text
local-transfer discover [--events] [--window SECONDS] [--stale-after SECONDS]
```

The `discover` command observes the local network for a bounded window (`--window`, default three seconds, range 1–60), feeds every validated observation into the core discovery lifecycle state, and prints the devices that are currently visible. It performs no discovery parsing, compatibility checking, coalescing, or expiry of its own; those belong to `local-transfer-core`.

Every run begins with a reminder that discovery is advisory and unauthenticated: a listed device is only currently advertising on the local network. It is not paired, trusted, or authenticated, and its name, platform, and addresses are unverified hints. Devices are identified by a transient per-session key rather than a persistent identity, so two devices that share a display name stay distinguishable by that key and their addresses. Devices are listed in a deterministic order by session key.

With `--events`, each observed lifecycle transition is printed before the device list: `appeared`, `refreshed`, `updated`, `removed`, `expired`, `ignored` (a no-op such as an already-absent removal), and `rejected` (a malformed or incompatible observation, shown as a safe message with no raw network detail). A `refreshed` observation is never presented as a new appearance.

`--stale-after SECONDS` (range 1–3600) asks core to drop devices that have not been re-observed within that many seconds; with `--events` this is reported as an `expired` line, distinct from an explicit `removed`. The staleness rule, tombstoning, and ordering all live in `local-transfer-core`; the CLI only supplies the threshold and the current observation time. Without the flag, devices are never expired during the pass.

Results go to standard output. A failure to start discovery, or a failure to stop it cleanly, is written to standard error with a non-zero exit status. Pressing Ctrl+C requests cancellation: the observation loop stops promptly, the browser session is still stopped gracefully, and the results collected so far are printed. The browser session is always stopped before the command exits.

## Command philosophy

- Prefer clear nouns and verbs over compact but obscure flags.
- Make interactive consent explicit and provide non-interactive behavior only when it is safe and unambiguous.
- Keep human output readable while designing a stable machine-readable mode for automation.
- Send results to standard output, diagnostics to standard error, and return meaningful exit codes.
- Do not expose secrets in arguments, output, process listings, shell history, or logs.
- Use stable peer identifiers when names are ambiguous; display names are conveniences, not identities.
- Surface the same core states and security decisions as the desktop application.

## Future conceptual commands

```text
local-transfer devices
local-transfer pair <device>
local-transfer peers
local-transfer send file.zip <device>
local-transfer send file1 file2 <device>
local-transfer receive
local-transfer status
```

The likely intent is:

- `devices`: summarize currently visible devices and their trust state.
- `pair <device>`: initiate the user-verified pairing flow.
- `peers`: list and eventually manage trusted devices.
- `send <path>... <device>`: request transfer of one or more selected paths.
- `receive`: wait for and interactively accept or reject incoming requests.
- `status`: show active transfers and relevant local service state.

`discover` is implemented (see above) as a bounded observation of raw discovery lifecycle; `devices` is still expected to layer trust state and a friendlier summary on top of the same core state. The syntax separating multiple paths from the destination, and whether peer removal is a subcommand, still require usability testing. The first transfer implementation should support a single file before committing to multi-file syntax.

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
