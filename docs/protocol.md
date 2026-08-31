# Protocol

## Scope

This document defines the conceptual lifecycle shared by all interfaces. It deliberately does not select a serialization format, detailed message schema, port strategy, cryptographic construction, or concurrency model. Those choices should follow prototypes and security review while preserving the invariants below.

The initial transport direction is a direct LAN TCP connection secured with TLS after pairing. QUIC is a possible later evaluation, not an MVP requirement.

## Roles and identifiers

Either device may discover, pair with, send to, or receive from another device. “Sender” and “receiver” describe one transfer rather than permanent roles.

A device has a stable local identity backed by cryptographic key material. Human-readable names are labels and may collide or change; they must not be used as security identities. A network endpoint is transient and must not be the sole identity of a trusted peer.

## Discovery lifecycle

1. An available instance advertises a DNS-SD service, initially expected to be `_local-transfer._tcp`.
2. Another instance browses for that service and resolves enough information to attempt a connection.
3. The discovered endpoint appears as untrusted unless it matches a trusted identity through a later authenticated exchange.
4. Advertisements expire or are removed when the service is no longer reachable.

Discovery data should be limited to service location, protocol compatibility information, and a non-sensitive presentation hint if usability requires one. The final TXT record fields and privacy tradeoffs remain to be decided. Discovery must never expose filenames, file sizes, transfer history, trusted-peer lists, or private identity data.

Discovery is advisory. Every endpoint and advertised value must be validated, and peer identity must be established by pairing or authenticated transport rather than mDNS.

## Pairing lifecycle

1. A user selects a discovered device and requests pairing.
2. The devices negotiate a supported pairing method and exchange ephemeral or identity information as required by an established construction.
3. Both users complete a verification or confirmation step that resists active interception.
4. Each device binds the verified peer identity to its authenticated public-key material.
5. The trust record is stored locally and the outcome is reported to both interfaces.
6. Rejection, timeout, mismatch, or protocol failure produces no trusted relationship and leaves no ambiguous partial state.

Repeated pairing requests must be bounded. Re-pairing, identity reset, revocation, and key rotation need explicit semantics before the pairing protocol is finalized.

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

- Service advertisement fields and listener-port lifecycle.
- Message framing and serialization format.
- Pairing construction and user-verification experience.
- TLS identity representation and pinning mechanism.
- Capability and version negotiation rules.
- Per-transfer integrity and optional resumability.
- Limits, timeouts, rate controls, and parallel transfer policy.
- Collision handling, temporary file naming, and completion acknowledgement.
