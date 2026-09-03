# Trust and pairing

## Scope

This document specifies the trusted-peer model and the pairing lifecycle: how
`local-transfer` moves a device from unauthenticated discovery to an explicitly
trusted peer relationship, and how that relationship is inspected, changed,
reset, and revoked.

It is a design and contract document for later implementation issues. It does
not select a cryptographic construction, key type, serialization format, wire
schema, storage format, timeout constant, or user-interface layout. Those follow
prototypes and security review while preserving the invariants below. Nothing
here authorizes adding cryptography, key storage, pairing code, persistence
schema, or CLI pairing commands; those are separate issues.

The threat model in [security.md](security.md), the lifecycle in
[protocol.md](protocol.md), the component boundaries in
[architecture.md](architecture.md), and the principles in
[../AGENTS.md](../AGENTS.md) remain authoritative. This document refines the
trust-specific parts of those sources and must stay consistent with them.

## Relationship to other documents

- [security.md](security.md) owns the overall security goals and network threat
  model. Its "Trust model" and "Pairing" sections state the requirements; this
  document specifies the state model that satisfies them.
- [protocol.md](protocol.md) owns the conceptual connection and transfer
  lifecycle and the discovery lifecycle. Its "Pairing lifecycle" section is the
  wire-facing view; this document is the core state-machine view.
- [architecture.md](architecture.md) owns the dependency direction and the
  core/adapter split. This document assigns trust responsibilities within that
  split.

## Existing terminology audit

Before defining new terms, this section records what the repository already
means, which identifiers are transient or persisted, and where existing text is
imprecise. Corrections are called out explicitly rather than applied silently.

### Local device identity

- `DeviceId` (`crates/local-transfer-core/src/identity.rs`) is an opaque,
  randomly generated UUID version 4. `architecture.md` calls it "the stable
  installation identity"; it is persisted as the `device-id` file with
  restrictive permissions. `security.md` states plainly that it is **not a
  cryptographic secret** and is **never advertised**.
- `DeviceName` is a separate mutable, user-facing label persisted as
  `device-name`. It is presentation only.
- `Platform` is bounded descriptive metadata derived from the compilation
  target. `architecture.md` states it "is never an identity or trust input".

### Discovery identity

- `TransientDiscoveryKey` (`crates/local-transfer-core/src/browser.rs`) is a
  session-scoped DNS-SD service fullname (`lt-<uuid>._local-transfer._tcp.local.`).
  It exists only to correlate resolution, update, and removal events within one
  browsing session. It is never persisted and "grants no trust or
  authorization".
- The advisory `name` hint (`DiscoveryNameHint`) and `os` hint
  (`DiscoveryPlatformHint`) are explicitly "unauthenticated, non-authoritative,
  and may be absent".
- Resolved endpoints, addresses, ports, the ephemeral `lt-<uuid>` service
  instance label, the `.local.` hostname, and any name-conflict suffixes are all
  transient.
- `DiscoveredPeer` / `DiscoveredPeerState` model currently visible
  advertisements. Their documentation repeatedly states that visibility "never
  establishes identity, pairing, trust, authentication, or authorization".

### Transient versus persisted identifiers

| Identifier | Lifetime | Persisted |
| --- | --- | --- |
| `DeviceId` | Installation | Yes (`device-id`, local only, never sent) |
| `DeviceName` | Until changed | Yes (`device-name`, presentation only) |
| `TransientDiscoveryKey` | One browsing session | No |
| Ephemeral service instance / hostname / conflict suffix | One advertisement session | No |
| Resolved endpoints, addresses, ports | Per resolution | No |
| Discovery tombstones | Bounded in-memory window | No |
| Trusted-peer record | Until reset or revoked | Yes (future issue; see below) |
| Device cryptographic identity (keypair) | Installation, until reset/rotation | Yes (future issue #35) |

### Security terminology already in use

"advisory", "unauthenticated", "untrusted", "hostile input", "trusted-peer
record", "explicit pairing", "authenticated key material", "user-verifiable
step", "short authentication string", "pinning", "identity change", "revoked",
"reset", and "per-transfer consent" / "explicit consent for incoming
transfers".

### Conflations and imprecise wording to correct

1. **"peer" is overloaded.** `DiscoveredPeer` and `DiscoveredPeerState` use
   "peer" for advisory, unauthenticated discovery snapshots, while `cli.md`
   uses "peers" (the future `peers` command) for *trusted* devices. Correction:
   in trust-relevant text, always qualify the noun as **discovered peer** or
   **trusted peer**. A bare "peer" must not appear in a security decision.

2. **`DeviceId` versus device cryptographic identity.** `protocol.md` says "A
   device has a stable local identity backed by cryptographic key material."
   That describes the *future* device cryptographic identity (open issue #35),
   not `DeviceId`. Correction: `DeviceId` is local installation bookkeeping,
   is never transmitted, and is **never** the identity a trusted-peer record
   binds to. The two must not be conflated.

3. **"a stable peer identifier".** `security.md` says a trusted-peer record
   should "bind a stable peer identifier to authenticated key material". Read
   literally this invites binding to something like `DeviceId` or a discovery
   key. Correction (applied in this document and mirrored in `security.md`):
   the stable identifier is a **local record identifier** with no security
   meaning, plus the **authenticated peer key identity** that carries all
   security meaning.

4. **"reset" versus "revocation".** `security.md` and `roadmap.md` use both
   words for "trust no longer applies" without distinguishing them. This
   document defines each (see [Reset and revocation](#reset-and-revocation)).

5. **"known".** The word appears loosely ("otherwise known endpoint" in
   `protocol.md`). This document does not introduce a distinct "known" trust
   tier; a device is either untrusted or trusted, with an explicit
   identity-changed sub-state.

### Documentation gaps this document fills

- No prior definition of a pairing *attempt* as a state machine distinct from
  trust.
- No defined identity-change / recovery flow.
- No distinction between local reset and revocation.
- No ownership split for trust between core, transport/crypto adapter, UI, and
  persistence.
- No explicit trusted-peer record field list.
- No threat-scenario walkthrough for pairing and trust.

## Security model boundaries

### 1. Discovery

Discovery answers exactly one question: *what is currently advertising the
`_local-transfer._tcp` service nearby?* It does not establish who controls a
device, whether it is the same device seen before, whether its key is
authentic, whether it is trusted, or whether it may send or receive a transfer.
All discovery metadata is advisory and attacker-controlled.

Discovery **can never create or upgrade trust**. No number of observations, no
matching `name` hint, and no reused `TransientDiscoveryKey` moves a device out
of the untrusted state. Discovery appearance, refresh, update, expiry, and
removal never change trust state, and a peer being offline is never equivalent
to being untrusted or revoked.

### 2. Authenticated cryptographic identity

A trusted-peer record binds to the remote device's **authenticated public-key
identity**, conceptually:

- authenticated public-key identity material for the remote device;
- a stable cryptographic fingerprint/identifier derived from that key material,
  suitable for comparison and display;
- protocol-established proof that the remote party currently possesses the
  corresponding private key.

The concrete key type, fingerprint construction, and proof-of-possession
mechanism are deferred to the cryptographic-identity and transport issues
(#34, #35, #36, #38, #39). This document only requires that whatever is chosen
is an **established construction from a maintained library** and that core
consumes an already-validated result.

A `TransientDiscoveryKey`, display name, hostname, IP address, port, or endpoint
must never be promoted into this identity.

### 3. Pairing attempt

A pairing attempt is a transient, in-memory object owned by
`local-transfer-core`. It is **not trust** and is **never persisted**. Its
lifecycle:

| Attempt state | Meaning |
| --- | --- |
| `Started` | The user explicitly initiated pairing with a selected target. |
| `AwaitingAuthentication` | The transport/crypto adapter is running the established handshake / key agreement / proof of possession. |
| `AwaitingUserVerification` | An authenticated transcript exists; a short authentication representation is presented and awaits explicit confirmation. |
| `Verified` | The user explicitly confirmed the representation **and** the authenticated protocol state is valid. |
| `Committing` | Core is atomically persisting the trusted-peer record. |
| `Failed` | Authentication failure, malformed input, unsupported version, unexpected transition, transport loss, or persistence failure. Terminal. |
| `Mismatched` | The user reported that the authentication representations differ. Terminal. |
| `Cancelled` | The user or the remote party aborted the attempt. Terminal. |
| `TimedOut` | The attempt deadline elapsed before verification and commit. Terminal. |

No attempt state except a successful `Committing` may create persistent trust.
Every terminal failure state leaves **no** trusted-peer record and no partial
trust.

### 4. User-verifiable step

Before trust is established the user must take an explicit, affirmative
verification action. The specification requires an **established human
verification construction**, such as comparing a short authentication string
(SAS) computed from the authenticated pairing transcript, or confirming an
equivalent established out-of-band signal. `local-transfer` must not design a
custom SAS or comparison scheme.

Rules:

- The user must **explicitly confirm** a match. Absence of a response, a closed
  window, or an expired prompt is never a confirmation.
- Matching display names, matching `os` hints, and any other discovery metadata
  are irrelevant to verification and can never substitute for it.
- Mismatch, cancellation, timeout, malformed input, and protocol failure all
  fail closed: the attempt becomes terminal with no trusted-peer record.
- User confirmation alone is insufficient. Core commits trust only when the
  authenticated protocol state is *also* valid at commit time. A confirmation
  received for an attempt whose authentication has failed is discarded.

### 5. Trusted-peer record

The minimum conceptual record core needs:

| Field | Purpose | Notes |
| --- | --- | --- |
| Local record identifier | Stable handle for UI and commands | No security meaning; opaque; not derived from remote data |
| Authenticated peer key identity / fingerprint | The single security-relevant binding | All trust decisions key on this value |
| User-facing label | Let the user recognize the record | Presentation only; set locally; may be seeded from a discovery hint at creation but is not authoritative and never participates in a trust decision |
| Trust establishment timestamp | Ordering and user context | Include only if the product genuinely needs it |
| Local trust status | Distinguishes active trust from an identity-changed / suspect record | Required only if persistence must represent the suspect state |

The record **must not** persist: transient discovery keys, current IP addresses,
interfaces, ephemeral endpoints, unverified hostnames, raw pairing transcript
material beyond what authentication binding requires, or discovery hints treated
as authoritative. Any exception requires an explicit, written security
justification in the implementing issue.

Trusted cryptographic identity and presentation metadata are separate: the
fingerprint authenticates; the label only helps a human read the list.

Persisting trusted-peer records is a later issue (#20). This document defines
the shape; it does not add storage.

### 6. Identity change

An identity-change condition exists when **all** of the following hold:

- a trusted-peer record exists;
- a newly authenticated connection claims to represent that record (for example
  by connecting as that trusted peer);
- the authenticated key identity presented **differs** from the fingerprint
  stored in the record.

Required behavior:

- The system **must not** silently replace or update the stored key.
- The record enters an explicit **identity-changed (suspect)** condition. This
  is **not a third trust tier and not a "partially trusted" state**:
  `identity-changed == not effectively trusted`. Effective trust for the
  relationship is false.
- While identity-changed, the relationship **must not** authorize any of:
  authenticated peer acceptance through the old relationship, acceptance of the
  newly presented identity, any file transfer, automatic key replacement, or
  automatic re-pairing.
- The stored old trusted fingerprint may be retained locally, but only as
  warning, audit/context, and user-recovery comparison material. Retaining it
  never confers authorization.
- The device remains discoverable; discovery is unaffected.
- The condition is surfaced to the user through an explicit, user-visible
  recovery flow.
- Discovery name equality, endpoint equality, or platform-hint equality never
  weakens this behavior.

Recovery requires an explicit user choice:

- **Reject / revoke**: remove or revoke the existing record. The new identity is
  then an ordinary untrusted device that requires a fresh pairing.
- **Re-pair**: run a full pairing attempt for the new identity, including the
  complete user-verifiable step, at the same bar as a first pairing. Only a
  successful `Committing` transition rebinds the record.

### 7. Reset and revocation

Local reset and revocation both remove effective trust. They differ only in
intent:

- **Local reset (forget)**: the user intentionally forgets the trust
  relationship on this device — decluttering, retiring a device, or starting
  over. Neutral; no judgment that the peer is hostile.
- **Revocation**: the user actively decides a previously trusted identity should
  no longer be accepted — suspected compromise, a lost device, or a failed
  identity-change recovery. In this project revocation is a **local trust
  decision only**. It is not a CRL, not certificate-authority infrastructure,
  and not a network-wide or distributed revocation signal, unless a future
  protocol explicitly adds broader semantics.

Both end in the same place: no effective trust, the peer stays discoverable, and
re-establishing trust requires a fresh explicit pairing attempt.

#### Effective runtime trust versus durable state

Trust establishment fails closed: a newly verified trusted-peer record that
cannot be committed atomically never makes the runtime trusted (transition
row 11; [Error and failure model](#error-and-failure-model)). The inverse
operation fails closed the same way.

**Effective runtime trust** is the authorization the running process actually
grants. Once core accepts a reset or revocation request:

- effective trust for the relationship becomes false immediately;
- the current authenticated session and every subsequent session in that
  process receive no trusted-peer authorization from that relationship;
- any transfer that depends on that trust is refused.

This takes effect regardless of whether the durable store can be updated.

**Durable state** is a separate durability step. If the persistence adapter
cannot durably record or remove the trust state, core must:

- report an explicit persistence/durability failure;
- **not** report the reset or revocation as durably successful;
- keep effective runtime trust disabled;
- surface clearly that the durable store may still contain the previous trusted
  record.

Unavoidable limitation: if no durable write can be completed, the implementation
**cannot guarantee that stale trust stays removed across a process restart or
power loss**. A future persistence design must therefore provide an atomic
durable representation of trust removal/revocation before claiming durable
success. This document does not choose that storage mechanism.

For the current project stage, `local-transfer` does **not** require durable
revocation history, a revocation list, or any certificate-authority-style
infrastructure. Whether revocation additionally leaves a *local* marker so the
same fingerprint cannot be re-trusted without an extra warning remains an open
decision (see [Open decisions](#open-decisions)); it is not built by this
specification. If no marker is kept, reset and revocation are operationally
identical and differ only in the wording shown to the user.

In both cases the effective-trust removal must be **deterministic**: after core
accepts the operation, no code path in the running process treats the peer as
effectively trusted, whether or not the durable write succeeded.

### 8. Retry and timeout

- Timeout leaves no trusted-peer record.
- Cancellation leaves no trusted-peer record.
- Malformed input and protocol failure leave no trusted-peer record.
- Verification mismatch leaves no trusted-peer record.
- A retry starts a brand-new pairing attempt in `Started`. It inherits no
  transcript, no partial verification, and no authentication state from any
  previous attempt.
- A previous failed attempt must never implicitly authorize or shortcut a
  retry. There is no hidden retry loop that lowers the verification bar.

Repeated pairing attempts against the same target must be bounded (rate and
count) so an attacker cannot use retries to fatigue the user into confirming.
The bound values are an implementation decision.

### 9. Per-transfer consent

`trusted peer != permission to transfer.`

Trust answers: *we have previously authenticated and explicitly accepted this
cryptographic peer identity.* Per-transfer consent answers: *do I allow this
specific transfer right now?* Trusting a peer never automatically accepts an
incoming file and never pre-authorizes an outgoing one. Per-transfer consent is
a separate security boundary defined by `protocol.md` ("Single-file transfer
lifecycle") and the transfer issues, not here.

## State-transition specification

### Trust relationship states

| State | Meaning | Effective trust | Persisted |
| --- | --- | --- | --- |
| Untrusted | No trusted-peer record for this authenticated identity. The default for every discovered or unknown device. | No | No record |
| Pairing | A pairing attempt referencing this target is in progress. Not trust. | No | No (in-memory attempt only) |
| Trusted | A committed trusted-peer record binds this authenticated key identity. | Yes | Yes |
| Identity-changed (suspect) | A trusted-peer record exists, but an authenticated exchange presented a different key identity. Not a third tier; `identity-changed == not effectively trusted`, pending explicit user action. | No | Record retained and flagged; never auto-accepted |

"Effective trust" is the authorization the running process grants. It is the
security-relevant column: whenever it is `No`, the relationship authorizes
nothing. After an accepted reset or revocation whose durable write then fails
(transition row 20), effective trust is `No` while a stale record may still sit
on disk; that is a durability failure to report, not a trusted state.

### Transitions

| # | From | Trigger | To | Guarantees |
| --- | --- | --- | --- | --- |
| 1 | Untrusted (discovered / unknown) | User explicitly starts pairing with a selected target | Pairing · `Started` | Discovery data only locates an endpoint; no trust implied |
| 2 | Pairing · `Started` | Transport/crypto adapter begins the established handshake | Pairing · `AwaitingAuthentication` | Core does not implement the handshake |
| 3 | Pairing · `AwaitingAuthentication` | Adapter returns a validated authenticated transcript and proof of possession | Pairing · `AwaitingUserVerification` | Core consumes an already-validated result |
| 4 | Pairing · `AwaitingAuthentication` | Authentication failure, malformed input, unsupported version, or unexpected message | Pairing · `Failed` (terminal) | Fail closed; no record |
| 5 | Pairing · `AwaitingUserVerification` | Both users explicitly confirm the short authentication representation matches | Pairing · `Verified` | Explicit affirmative action required; silence is not consent |
| 6 | Pairing · `AwaitingUserVerification` | User reports the representations differ | Pairing · `Mismatched` (terminal) | Fail closed; no record; treated as a possible active attacker |
| 7 | Pairing · `AwaitingUserVerification` | User declines or cancels | Pairing · `Cancelled` (terminal) | No record |
| 8 | Pairing · any non-terminal | Attempt deadline elapses | Pairing · `TimedOut` (terminal) | No record |
| 9 | Pairing · any non-terminal | Peer disconnects or transport error | Pairing · `Failed` (terminal) | No record |
| 10 | Pairing · `Verified` | Core atomically commits a trusted-peer record | Trusted | Trust exists only after this step |
| 11 | Pairing · `Verified` / `Committing` | Persistence cannot commit atomically | Pairing · `Failed` (terminal) | Pairing reported as failed; no trusted state; retry starts over |
| 12 | Pairing · any terminal | User retries | Untrusted, then a new Pairing · `Started` | New attempt shares no state with the failed one |
| 13 | Trusted | Authenticated connection presents the **same** bound key identity | Trusted (unchanged) | Normal reconnect; endpoints and discovery hints irrelevant |
| 14 | Trusted | Authenticated exchange presents a **different** key identity for this record | Identity-changed (suspect) | Effective trust false; no automatic trust or key replacement; user-visible alert; transfers blocked; old fingerprint kept only as recovery context |
| 15 | Identity-changed (suspect) | User runs explicit recovery: reject / revoke the old record | Untrusted | Fresh pairing required to trust the new identity |
| 16 | Identity-changed (suspect) | User runs explicit re-pair and completes full verification for the new identity | Trusted (new binding) | Same verification bar as a first pairing |
| 17 | Trusted | User requests local reset (forget); core accepts | Untrusted (effective) | Effective trust false immediately for current and later sessions; transfers refused; durable removal is a separate step |
| 18 | Trusted | User requests revocation; core accepts | Untrusted (effective) | Same immediate effect as row 17; revocation is a local distrust decision, not a network-wide signal |
| 19 | Untrusted (effective), after row 17 or 18 | Persistence durably records the removal / revocation | Untrusted (durable) | Reset / revocation reported as durably successful |
| 20 | Untrusted (effective), after row 17 or 18 | Persistence cannot durably write | Untrusted (effective); durability failure | Explicit persistence/durability failure reported; not reported as durably successful; stale durable record may survive restart until a durable write succeeds |
| 21 | Trusted, Identity-changed, or Untrusted | Discovered peer appears, refreshes, updates, expires, or is removed | unchanged | Discovery lifecycle never changes trust state; offline is not untrusted |
| 22 | Untrusted | Any discovery observation, matching `name` hint, or reused transient key | Untrusted (unchanged) | Advisory signals never create or upgrade trust |

### Notes

- Rows 1, 5, 6, 7, 12, 15, 16, 17, 18 are driven by explicit user intent
  supplied through a UI/CLI adapter.
- Rows 2, 3, 9 depend on results from the transport/crypto adapter.
- Rows 4, 8, 10, 11, 13, 14, 19–22 are decisions core makes and owns; rows
  19–20 also depend on the persistence adapter's durable result.
- Rows 17–20 are the fail-closed removal contract: effective trust drops the
  moment core accepts the request (rows 17–18), and durable success (row 19)
  versus durable failure (row 20) is reported distinctly. A durable failure
  never re-enables effective trust. This mirrors trust establishment, where
  row 11 withholds trust when the commit cannot be persisted.
- There is no transition from any terminal pairing-attempt state directly to
  Trusted. The only path to Trusted is row 10 or row 16.

## Error and failure model

These are conceptual categories, not Rust enums. Implementing issues define
concrete error types following the repository error conventions.

| Category | Fail-closed outcome |
| --- | --- |
| Timeout | Attempt terminal; no record |
| Cancellation (local or remote) | Attempt terminal; no record |
| Malformed pairing input | Attempt terminal; no record; no raw attacker data surfaced |
| Unsupported protocol or version | Attempt terminal; no record |
| Authentication failure | Attempt terminal; no record |
| Verification mismatch | Attempt terminal; no record; surfaced as a possible attack |
| Unexpected state transition | Attempt terminal; no record; treated as a bug or hostile input |
| Trusted identity mismatch / change | Record moves to identity-changed (suspect); effective trust false; no auto-accept, no key replacement; transfers blocked |
| Persistence failure while committing trust | Pairing reported as **failed**; no trusted state; safe to retry |
| Reset / revocation persistence failure | Effective runtime trust already disabled and stays disabled; explicit persistence/durability failure reported; **not** reported as durably successful; user told the durable store may still hold the old record; stale trust cannot be guaranteed removed across restart until a durable write succeeds |

Overriding rule, both directions: **if durable trust cannot be committed
atomically, the system must not report pairing success**, and **if durable
removal cannot be completed, the system must not report reset or revocation as
durably successful**. Trust establishment and trust removal both fail closed;
the safe outcome is always "not effectively trusted". A removal disables
effective runtime trust immediately, and only the durability claim waits on the
persistence adapter.

Wire and log output for any of these must reveal no secrets, no pairing
material, and no unnecessary local detail, consistent with `security.md`.

## Ownership boundaries

### `local-transfer-core`

Owns the security-sensitive semantics:

- the pairing-attempt state machine and all attempt-state transitions;
- the trusted-peer model and the meaning of the authenticated key binding;
- the set of allowed trust-relationship transitions (the table above);
- identity-change detection (comparing a presented fingerprint to the stored
  one);
- reset and revocation semantics: dropping effective runtime trust immediately
  when the request is accepted, and reporting durable success only on a
  confirmed durable write;
- every fail-closed decision, including "user confirmed but authentication is
  invalid", "verified but persistence failed", and "removal accepted but durable
  write failed";
- the rule that discovery events never mutate trust state.

Core consumes already-validated authentication results. It does not implement
key agreement, signatures, or channel encryption.

### Transport / crypto adapter

Eventually owns the implementation-specific operations, behind a narrow
interface, per `architecture.md`:

- the established handshake / authenticated key agreement;
- proof of possession of the private key;
- the authenticated transcript and the material a SAS is derived from;
- secure channel establishment and binding the channel to the stored key
  (pinning or an established equivalent).

It reports validated outcomes and typed failures to core; it never writes trust
state.

### CLI / UI adapter

Owns presentation and the explicit user actions:

- presenting the verification representation and any authenticated context;
- capturing the explicit confirm / reject / cancel actions;
- rendering timeout, mismatch, identity-change, and failure states as described
  in `cli.md` and `desktop.md`;
- confirming reset and revocation with the user.

The adapter cannot mark a discovered peer as trusted directly. Its only route to
Trusted is to drive a core pairing attempt that reaches a valid commit.

### Persistence adapter

Eventually owns durable-storage mechanics only:

- atomic writes and no-clobber / replace semantics consistent with the existing
  identity stores;
- restrictive permissions where the platform supports them;
- reporting durable success, or an explicit durability failure, for a trust
  commit or a trust removal.

It does not define trust semantics, validity, or transitions, and it never
reinterprets what effective trust means; a durability failure it reports leaves
core's effective-trust decision untouched.

## Threat-oriented review

Each scenario is checked against the model above.

- **Attacker advertises the same display name as a trusted peer.** Display names
  are presentation only (audit correction 1). Trust keys on the authenticated
  fingerprint. The attacker cannot authenticate as the trusted key, so it stays
  untrusted; starting a pairing with it would still require the full
  user-verifiable step. No effect on trust.
- **Attacker reuses an old `TransientDiscoveryKey`.** The transient key is never
  an identity and never appears in a trusted-peer record. At most it seeds an
  advisory entry in discovery state. Authentication is still required to do
  anything trust-relevant. No effect.
- **Trusted peer changes IP or interface.** Endpoints are not stored in the
  trusted-peer record (section 5). Reconnection re-authenticates against the
  bound fingerprint. Trust is unaffected (row 13).
- **Trusted peer goes offline and returns.** Discovery removal or expiry does
  not touch trust (row 21). On return, the same key authenticates and the peer
  is still Trusted. Offline never means revoked.
- **Authenticated key changes.** Detected as an identity change (row 14). The
  record becomes identity-changed (suspect); trust is withheld and transfers are
  blocked until explicit recovery (rows 15–16).
- **Record in identity-changed / suspect condition.** Neither the old stored
  fingerprint nor the newly presented key identity is automatically authorized
  (`identity-changed == not effectively trusted`, row 14). The device stays
  discoverable. The old fingerprint is retained only as comparison/recovery
  context and never authorizes acceptance, a transfer, key replacement, or
  re-pairing. Escaping the condition requires an explicit user choice —
  reject/revoke, or a full re-pair at the first-pairing verification bar
  (rows 15–16).
- **Pairing is interrupted before user confirmation.** The attempt ends
  `Cancelled`, `TimedOut`, or `Failed` (rows 7–9). Atomicity guarantees no
  record and no partial trust.
- **User confirms but protocol authentication has failed.** `Verified` requires
  both the explicit confirmation and a valid authenticated protocol state
  (section 4, row 5). If authentication has failed the attempt is `Failed`
  regardless of a stray confirmation, and core does not commit.
- **Persistence fails after verification.** Row 11: the pairing is reported as
  failed, no trusted state is written, and the user may retry from scratch.
- **Pairing times out and is retried.** Row 12: a fresh attempt in `Started`
  with no inherited state; the full verification runs again.
- **Reset peer is rediscovered.** It appears as an ordinary untrusted discovered
  peer. Re-trust requires a fresh pairing (rows 17, 1).
- **Revoked peer continues advertising.** It stays discoverable but untrusted;
  transfers are refused. Re-trust requires a fresh pairing, plus an extra
  warning if a local revocation marker is kept (row 18, section 7).
- **Revocation (or reset) persistence failure.** The user revokes a trusted peer
  but the durable write fails. Effective runtime trust for the relationship is
  already false and stays false: the current and later sessions in the process
  get no authorization from it and transfers are refused (rows 17–18, 20). Core
  reports an explicit persistence/durability failure and does **not** claim
  durable revocation; the user is told the durable store may still contain the
  old record. Until a durable write succeeds, removal cannot be guaranteed to
  survive a process restart or power loss.

In every scenario the model fails safe: trust is neither created nor retained
without an explicit, verified, atomically committed pairing, and an accepted
removal always disables effective trust even when its durable write fails.

## Open decisions

- The cryptographic identity type, fingerprint construction, and
  proof-of-possession mechanism (issues #34, #35, #36, #38, #39).
- The established pairing construction and the exact user-verification
  experience (SAS length, presentation, one-sided versus two-sided
  confirmation).
- Whether revocation keeps a durable local marker that blocks silent re-trust of
  the same fingerprint, or whether reset and revocation are operationally
  identical.
- The atomic durable representation of trust removal / revocation that lets the
  system claim durable success — deferred to the trusted-peer storage issue
  (#20).
- Pairing attempt timeout duration and the retry rate/count bounds.
- The trusted-peer storage format and location (issue #20), including whether
  the identity-changed state is persisted or recomputed on next contact.
- Whether the trusted-peer label may be edited after creation and how it is
  seeded.
- How a local device cryptographic identity reset is communicated to peers that
  still trust the previous identity (roadmap Phase 1 / Phase 3 boundary).

## Future issues that should follow this specification

- #18 Implement pairing request flow
- #19 Implement pairing accept/reject flow
- #20 Persist trusted peers
- #21 Add peer removal/revocation
- #22 Add CLI pairing commands
- #23 Add pairing tests
- #36 Authenticate paired peers
- #38 Pin trusted peer identity after pairing
- #39 Handle peer key/certificate changes safely
- #46 Implement `local-transfer pair`
