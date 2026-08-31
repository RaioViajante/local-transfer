# Security

## Security goals

`local-transfer` must protect file contents, device identity, and user intent on a network that may contain hostile participants. It must authenticate previously paired peers, require explicit consent for new trust and incoming transfers, and prevent received metadata from escaping the chosen destination or causing unsafe filesystem behavior.

Availability against a fully hostile local network cannot be guaranteed. The implementation should nevertheless bound resource use, reject malformed input, and make denial-of-service attacks harder.

## Trust model

The local network is untrusted. Finding a device through mDNS/DNS-SD proves only that an endpoint advertised a service; it does not prove who controls it. Display names, addresses, and discovery identifiers are hints, not authentication claims.

Trust is established per device through explicit pairing. A trusted-peer record should bind a stable peer identifier to authenticated key material and the user-visible identity needed to recognize it. Trust persists until it is revoked, reset, or invalidated by an identity change. A device presenting unexpected key material must not be silently accepted as the previously trusted peer.

Trusting a device authorizes authenticated communication; it does not automatically authorize every incoming file. Transfer acceptance remains a distinct user decision unless a narrowly scoped future policy explicitly changes that behavior.

## Pairing

Pairing should use an established authenticated key-agreement or secure-channel construction from maintained cryptographic libraries. The flow must include a user-verifiable step, such as comparing a short authentication string or confirming an equivalent out-of-band signal, so an active LAN attacker cannot transparently pair in the middle.

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

The exact history retention and deletion policy remains unresolved and must be visible to both CLI and desktop users.

## Security review gates

Before the first usable transfer release, the project should document the selected pairing construction, transport peer binding, key storage, protocol limits, filename rules, overwrite behavior, temporary-file handling, and concurrent-instance model. These areas require tests across all supported operating systems and focused review rather than assumptions inherited from one platform.
