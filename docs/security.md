# Security

## Security goals

`local-transfer` must protect file contents, device identity, and user intent on a network that may contain hostile participants. It must authenticate previously paired peers, require explicit consent for new trust and incoming transfers, and prevent received metadata from escaping the chosen destination or causing unsafe filesystem behavior.

Availability against a fully hostile local network cannot be guaranteed. The implementation should nevertheless bound resource use, reject malformed input, and make denial-of-service attacks harder.

## Trust model

The local network is untrusted. Finding a device through mDNS/DNS-SD proves only that an endpoint advertised a service; it does not prove who controls it. Display names, addresses, and discovery identifiers are hints, not authentication claims.

The `_local-transfer._tcp` TXT schema is deliberately limited to discovery-schema and application-protocol compatibility plus optional bounded name and operating-system hints. It never advertises the permanent `DeviceId`. It also excludes hostnames, usernames, MAC or duplicated IP addresses, filesystem paths, filenames, transfer history or metadata, trusted-peer state, certificates, keys, fingerprints, tokens, secrets, hardware identifiers, and OS/kernel versions. Connection addresses and ports come from normal DNS-SD resolution.

Each advertisement uses an opaque UUID generated from operating-system-backed cryptographic randomness for its session-only service instance and `.local.` hostname. It is never persisted and does not embed the permanent `DeviceId`, `DeviceName`, system hostname, username, network address, or hardware identifier. Name-conflict suffixes selected by the DNS-SD implementation are likewise ephemeral. The TXT record remains limited to compatibility fields and optional advisory name and OS hints; resolved addresses and the caller-owned service port stay in standard DNS-SD records rather than TXT metadata.

The browser treats service fullnames, TXT entries, ports, and resolved addresses as hostile input. It exposes only schema-valid, protocol-compatible snapshots with a non-zero port and at most 16 deduplicated IPv4 or scoped IPv6 endpoints. The transient fullname exists only to correlate resolution, update, and removal events during the browser session; it is not `DeviceId`, is not persisted, and grants no trust or authorization. Removal concerns one advertisement, not permanent device identity or pairing state.

Self-discovery is allowed at this layer. Runtime composition may compare a local advertisement's ephemeral session name if filtering becomes useful, but discovery never guesses self from `DeviceId`, hostnames, addresses, MAC addresses, or other machine attributes.

Trust is established per device through explicit pairing. A trusted-peer record binds the peer's authenticated public-key identity (a stable cryptographic fingerprint derived from that key material) to a local record identifier that carries no security meaning and to a presentation-only label used to recognize it. `DeviceId`, hostnames, IP addresses, ports, and transient discovery keys are never that identity. Trust persists until it is revoked, reset, or invalidated by an identity change. A device presenting unexpected key material must not be silently accepted as the previously trusted peer; it enters an explicit identity-changed state that withholds trust until the user runs a visible recovery flow.

Trusting a device authorizes authenticated communication; it does not automatically authorize every incoming file. Transfer acceptance remains a distinct user decision unless a narrowly scoped future policy explicitly changes that behavior.

The trusted-peer record, the pairing-attempt state machine, the identity-change and recovery flow, reset versus revocation semantics, the fail-closed failure model for both trust establishment and trust removal, and the core/adapter ownership split are specified in [trust.md](trust.md). Reset and revocation remove effective runtime trust immediately when core accepts the request; a durable-persistence failure is reported explicitly and never keeps the peer effectively trusted, though it may leave a stale record on disk until a durable write succeeds. Revocation here is a local trust decision, not a network-wide or certificate-authority mechanism.

## Pairing

Pairing should use an established authenticated key-agreement or secure-channel construction from maintained cryptographic libraries. The flow must include a user-verifiable step, such as comparing a short authentication string or confirming an equivalent out-of-band signal, so an active LAN attacker cannot transparently pair in the middle. [trust.md](trust.md) specifies the attempt lifecycle, the explicit-confirmation rules, and the requirement that pairing fails closed on mismatch, cancellation, timeout, malformed input, protocol failure, or incomplete verification.

Pairing records should contain only what is required to recognize and authenticate the peer. Private identity keys must be generated with a cryptographically secure source, never leave the local device, and be stored using appropriate operating-system protection where practical. The precise identity format, pairing construction, key rotation policy, and recovery experience require a dedicated design review before implementation.

There will be no custom cipher, signature scheme, key derivation function, certificate format, or other cryptographic primitive.

## Network threat model

The design assumes an attacker on the LAN may:

- observe, inject, modify, replay, delay, or drop packets;
- publish deceptive discovery records and impersonate device names;
- scan or connect to exposed listening ports;
- send malformed or oversized protocol messages;
- attempt repeated pairing or transfer requests;
- attempt to exhaust connections, memory, disk space, or CPU.

Security controls should include authenticated peers, encrypted transport, protocol version and size bounds, timeouts, rate limits where appropriate, replay-resistant exchanges, explicit state machines, and conservative error handling. Discovery advertisements must not include filenames, file contents, transfer history, trusted-peer lists, or private key material.

Out of scope for the initial design are compromised endpoints, malicious files that the user opens after transfer, traffic-analysis resistance, anonymity, Internet relay, and guaranteed availability under sustained denial of service.

## Transport security direction

Transfers are expected to use TLS over a direct LAN connection after pairing. Authentication should bind the TLS peer to the key material established during pairing through certificate/public-key pinning or an established equivalent. Public certificate-authority identity is not an appropriate substitute for device pairing in this local, account-free system.

The project must use a maintained TLS implementation with safe defaults. Protocol versions, cipher configuration, certificate lifecycle, resumption behavior, and pin rotation will be selected after evaluating the chosen Rust ecosystem. QUIC may be evaluated later but is not required for the first version and does not change the authentication requirements.

Unauthenticated discovery and initial pairing traffic must never be treated as permission to transfer files. Sensitive application data should not be sent before the secure channel and peer binding have been validated.

## Filesystem safety

All received metadata is attacker-controlled, including filenames, relative paths, declared sizes, and content types. The receiver must:

- treat destination selection as a local decision;
- reject absolute paths, parent traversal, empty or reserved names, and path separators in single-file names;
- handle Windows reserved device names and cross-platform normalization differences;
- avoid following symlinks or reparse points outside the authorized destination;
- prevent overwrites unless the user has approved a clear conflict policy;
- write to a safely created temporary file and finalize atomically where the platform permits;
- clean up incomplete temporary data after rejection, failure, or cancellation;
- check declared sizes and available-space conditions where feasible;
- bound metadata, filename, message, and chunk sizes;
- preserve executable bits, permissions, alternate streams, and extended attributes only if a future explicit policy safely supports them.

The displayed filename and the actual opened destination must refer to the same validated value. Validation alone is insufficient if a later filesystem operation can race with directory or symlink changes; implementation should use platform-appropriate safe-open techniques.

## Local data and privacy

Persistence should be limited to identity keys, trusted peers, settings, and the minimum transfer metadata required for the intended experience. Sensitive values should have restrictive file permissions and use OS credential facilities where they materially improve key protection. Logs must avoid file contents, secrets, pairing material, and unnecessary full paths. There is no telemetry or analytics.

For current application-owned identity/configuration state, Unix-family systems enforce mode `0700` on the `local-transfer` configuration directory and `0600` on managed files, including correcting broader existing modes. Explicit test/adapter paths do not change an already-existing parent directory, but newly created immediate storage directories and all managed files are restrictive. On Windows, the application uses the per-user roaming configuration location and preserves its inherited ACLs; it does not yet install or claim a custom restrictive ACL. These filesystem controls limit local exposure but do not make `DeviceId` or `DeviceName` cryptographic secrets. Future private key material requires a separate secure-storage design.

The exact history retention and deletion policy remains unresolved and must be visible to both CLI and desktop users.

## Security review gates

Before the first usable transfer release, the project should document the selected pairing construction, transport peer binding, key storage, protocol limits, filename rules, overwrite behavior, temporary-file handling, and concurrent-instance model. These areas require tests across all supported operating systems and focused review rather than assumptions inherited from one platform.
