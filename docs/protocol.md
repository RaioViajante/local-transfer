# Protocol

## Scope

This document defines the conceptual lifecycle shared by all interfaces. It deliberately does not select a serialization format, detailed message schema, port strategy, cryptographic construction, or concurrency model. Those choices should follow prototypes and security review while preserving the invariants below.

The initial transport direction is a direct LAN TCP connection secured with TLS after pairing. QUIC is a possible later evaluation, not an MVP requirement.

## Roles and identifiers

Either device may discover, pair with, send to, or receive from another device. “Sender” and “receiver” describe one transfer rather than permanent roles.

A device has a stable local identity backed by cryptographic key material. This is distinct from `DeviceId`, which is local installation bookkeeping, is never transmitted, and is never the identity a trusted-peer record binds to. Human-readable names are labels and may collide or change; they must not be used as security identities. A network endpoint is transient and must not be the sole identity of a trusted peer. [trust.md](trust.md) specifies how a trusted-peer record binds to authenticated key identity.

## Discovery lifecycle

1. An available instance advertises the DNS-SD service `_local-transfer._tcp`.
2. Another instance browses for that service and resolves enough information to attempt a connection.
3. The discovered endpoint appears as untrusted unless it matches a trusted identity through a later authenticated exchange.
4. Advertisements expire or are removed when the service is no longer reachable.

Discovery schema version 1 has three required TXT entries: `dv=1` identifies the discovery metadata schema, while `pmin=1` and `pmax=1` describe the inclusive range of supported application-protocol major versions. Discovery-schema compatibility and application-protocol compatibility are separate: this release accepts only discovery schema 1, and two peers are application-compatible when their inclusive `pmin..=pmax` ranges overlap. An implementation should select the highest major version in the overlap.

Two optional presentation entries are defined: `name` is a UTF-8 hint of at most 96 bytes, and `os` is exactly `macos`, `windows`, or `linux`. Both are unauthenticated, non-authoritative, and may be absent. Invalid optional hints are discarded while otherwise valid compatibility metadata remains usable. Required values use canonical unsigned decimal text; missing, malformed, unsupported, reversed, or duplicated known fields invalidate the metadata. Unknown keys are ignored for forward compatibility after all size bounds are enforced.

Each TXT entry must fit the DNS-SD 255-byte length-octet limit. The complete encoded local-transfer TXT metadata, including each entry's length octet, is limited to 512 bytes. Local encoders emit only `dv`, `pmin`, `pmax`, `name`, and `os`. Addresses and ports come from DNS-SD SRV/A/AAAA resolution and are not duplicated in TXT metadata.

Discovery is advisory. Every endpoint and advertised value must be validated, and peer identity must be established by pairing or authenticated transport rather than mDNS.

Advertisements use `mdns-sd` as an internal synchronous DNS-SD adapter. The canonical service type is translated to `_local-transfer._tcp.local.` only at that boundary. Each start creates an opaque random `lt-<uuid>` service-instance label and matching `lt-<uuid>.local.` hostname; neither value is persisted or derived from `DeviceId`, `DeviceName`, the system hostname, or hardware. The library automatically tracks eligible IPv4 and IPv6 interface addresses and applies standard DNS name-conflict resolution. Conflict-selected names remain ephemeral.

The caller owns the listening TCP service and supplies its non-zero port; advertisement does not create the listener. A successful start means the daemon was created and accepted the registration request, not that multicast packets have already been transmitted. Later daemon errors and conflict name changes are available through non-blocking advertisement events. Explicit stop unregisters the service and shuts down its private daemon while waiting for bounded acknowledgements. Dropping an active handle only queues best-effort cleanup and cannot report failure. Browsing is handled separately from the advertisement lifecycle.

Browsing uses the same private `mdns-sd` adapter and canonical service type. A successful browser start means only that the browse command was accepted. Resolved TXT entries are passed through the discovery-schema validator, the advertised port must be non-zero, and the application protocol range must overlap `1..=1`. Malformed or incompatible advertisements produce diagnostics rather than compatible peer events.

A resolved advertisement is an unauthenticated snapshot keyed by its bounded transient DNS-SD fullname. That fullname is the only correlation key: repeated resolutions, additional interface addresses, and re-advertisement for the same fullname coalesce into that one snapshot, while the advisory `name` hint is never a correlation or identity key, so two devices that share a `name` remain separate discovered peers. Its addresses come only from DNS-SD resolution, preserve IPv4 and scoped IPv6, are deduplicated, and are limited to 16 unique endpoints. Resolved address and TXT ordering is not significant; an observation that differs from the current snapshot only by address order or repetition coalesces and emits `Refreshed` rather than `Updated`. The first valid resolution emits `Added`; meaningful validated changes emit `Updated`; identical repeats emit `Refreshed` so callers can update liveness without treating the observation as a semantic peer change. `Removed` is emitted only for a previously resolved transient key and means solely that this advertisement is no longer visible. It does not establish permanent presence or say that a physical device is offline.

Portable core discovery state consumes these validated browser events with caller-supplied monotonic times. It tracks current visibility for each transient advertisement name, coalescing repeated resolutions and extra interface addresses for that name into one visible peer, refreshes liveness on equivalent observations, applies meaningful snapshot updates, and can expire stale advertisements without reading a wall clock or scheduling timers. Recent per-key tombstones make duplicate removals and observations older than a removal or expiry deterministic no-ops while retained. Tombstones are bounded by both age and capacity; capacity pressure may deterministically evict the oldest tombstones before their retention horizon. After pruning or eviction, a valid observation may make the transient advertisement visible normally again. This state remains advisory and unauthenticated: visibility and repeated observation never establish identity, pairing, trust, authentication, or authorization.

## Pairing lifecycle

1. A user selects a discovered device and requests pairing.
2. The devices negotiate a supported pairing method and exchange ephemeral or identity information as required by an established construction.
3. Both users complete a verification or confirmation step that resists active interception.
4. Each device binds the verified peer identity to its authenticated public-key material.
5. The trust record is stored locally and the outcome is reported to both interfaces.
6. Rejection, timeout, mismatch, or protocol failure produces no trusted relationship and leaves no ambiguous partial state.

Repeated pairing requests must be bounded, and a retry starts a fresh untrusted attempt that inherits no state from a failed one. The core state machine for the pairing attempt, trusted-peer records, identity-change detection and recovery, and local reset versus revocation is specified in [trust.md](trust.md). Key rotation semantics still need to be resolved before the pairing protocol is finalized.

## Connection lifecycle

After pairing, a device may open a direct connection to a discovered or otherwise known endpoint. The secure transport handshake must authenticate the endpoint against the stored peer binding. A valid network route and a valid TLS handshake are both necessary; neither is sufficient without the expected peer identity.

Application negotiation should establish a compatible protocol version and capabilities. Unknown versions, unsupported required features, excessive messages, invalid state transitions, and authentication mismatches must fail closed. Compatibility negotiation should allow additive evolution without implying that every future feature must be understood by older peers.

## Single-file transfer lifecycle

The first transfer milestone should support one regular file:

1. The sender opens the local file and prepares bounded metadata, including a display name and declared byte size.
2. Over an authenticated channel, the sender creates a transfer request with an identifier unique enough for the connection or session.
3. The receiver validates the request and presents it for explicit accept or reject.
4. On acceptance, the receiver chooses or confirms a safe destination and creates an incomplete output safely.
5. The sender streams bounded chunks. Both sides track bytes transferred and emit progress without buffering the complete file.
6. Either side may request cancellation; disconnects and I/O failures also terminate the transfer.
7. On successful completion, the receiver verifies the agreed completion conditions and finalizes the file. Otherwise it removes or clearly quarantines incomplete data.
8. Each side reports a terminal result exactly once to its interface.

Backpressure must make the faster side respect the slower network or disk. Progress is informational and must be derived from actual I/O rather than trusting remote claims. The integrity mechanism, whether supplied entirely by the secure transport or supplemented by an end-to-end digest, remains to be evaluated.

## Cancellation and failure

Cancellation is a protocol and core-state operation, not merely a hidden window or interrupted progress display. It should be idempotent and lead to a defined terminal state. A peer may not receive a cancellation message when connectivity is lost, so both sides must also handle abrupt termination and timeout.

Failures should distinguish user rejection, user cancellation, authentication failure, incompatible protocol, invalid metadata, unavailable space, local I/O failure, remote failure, and connection loss where practical. Wire errors must reveal no secrets and should not expose unnecessary local filesystem details.

## Evolution

Every message family should eventually have explicit bounds and a versioning strategy. Extensions should be capability-negotiated, with safe behavior for unknown optional fields and rejection of unsupported required behavior.

Later protocol work may add multiple files, directories, clipboard/text payloads, resumable transfers, or QUIC. These features should extend the request and streaming model rather than bypass pairing, authenticated transport, user consent, or filesystem safety.

## Open protocol decisions

- Message framing and serialization format.
- Pairing construction and user-verification experience (trust-state semantics are settled in [trust.md](trust.md)).
- TLS identity representation and pinning mechanism.
- Capability and version negotiation rules.
- Per-transfer integrity and optional resumability.
- Limits, timeouts, rate controls, and parallel transfer policy.
- Collision handling, temporary file naming, and completion acknowledgement.
