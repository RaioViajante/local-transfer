//! Pairing-request phase: initiator and responder.
//!
//! This module implements only the first phase of a pairing attempt — an
//! explicit, local decision to begin pairing between two currently untrusted
//! devices — as two deterministic state machines that share one small bounded
//! wire message family:
//!
//! - [`PairingRequest`]: the initiator asks a device to begin pairing.
//! - [`PairingResponse`]: the responder presents an incoming request for an
//!   explicit local decision and emits the accept or reject reply.
//!
//! Reaching either machine's successful terminal state
//! (`…State::ReadyForNextPairingStage`) means only that this side finished its
//! local request-phase work and the attempt may proceed to the next,
//! authenticated pairing stage. Neither side asserts that the remote received
//! anything: for the initiator it is having received a valid acceptance reply,
//! for the responder it is the caller reporting a successful local transport
//! send of its acceptance reply. It never means the remote device is trusted,
//! authenticated, verified, or authorized for any transfer. There is no
//! trusted-peer record anywhere in this module, nothing here is persisted, and
//! no cryptography is performed. The authenticated key agreement, the
//! user-verifiable step, and any cryptographic-identity or SAS mismatch are
//! separate later issues; see `docs/trust.md` and `docs/protocol.md`.
//!
//! Both machines read no clock: callers supply monotonic [`Duration`] values and
//! an explicit deadline. Neither retries on its own. A retry is a brand-new
//! state-machine object — the initiator calls [`PairingRequest::initiate`]
//! again, the responder builds a new [`PairingResponse`] from a fresh incoming
//! request — sharing no state with the previous attempt.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use uuid::Uuid;

/// The pairing-request protocol version implemented by this release.
pub const PAIRING_PROTOCOL_VERSION: u8 = 1;

const VERSION_OFFSET: usize = 0;
const KIND_OFFSET: usize = 1;
const ATTEMPT_ID_OFFSET: usize = 2;
const ATTEMPT_ID_LEN: usize = 16;
const REASON_OFFSET: usize = ATTEMPT_ID_OFFSET + ATTEMPT_ID_LEN;
const BASE_MESSAGE_LEN: usize = ATTEMPT_ID_OFFSET + ATTEMPT_ID_LEN;
const REJECTED_MESSAGE_LEN: usize = BASE_MESSAGE_LEN + 1;

/// The maximum encoded size, in bytes, of any pairing-request-phase message.
///
/// A decoder must reject anything longer before inspecting it.
pub const MAX_PAIRING_MESSAGE_BYTES: usize = REJECTED_MESSAGE_LEN;

const KIND_REQUEST: u8 = 1;
const KIND_REQUEST_ACCEPTED: u8 = 2;
const KIND_REQUEST_REJECTED: u8 = 3;

const REASON_UNSPECIFIED: u8 = 0;
const REASON_BUSY: u8 = 1;
const REASON_DECLINED: u8 = 2;

/// A bounded, non-cryptographic token that correlates the messages of one
/// transient pairing attempt.
///
/// The initiator core mints a fresh one inside
/// [`PairingRequest::initiate`](PairingRequest::initiate) for every attempt.
/// It is never persisted and is never a peer identity, a credential, proof of
/// possession, or a trust anchor. Anyone who observes the pairing request can
/// copy it, so it provides message correlation only, not authentication.
///
/// The value is opaque to callers: obtain it from
/// [`PairingRequest::attempt_id`], compare it, or display it. Its fixed 16-byte
/// wire form is internal plumbing for the message codec.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PairingAttemptId(Uuid);

impl PairingAttemptId {
    /// Generates a fresh attempt identifier from operating-system randomness.
    ///
    /// Crate-internal: [`PairingRequest::initiate`] owns token creation so every
    /// attempt gets a fresh one.
    #[must_use]
    fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Reconstructs an attempt identifier from its 16-byte wire form.
    ///
    /// Every 16-byte value is accepted: the identifier is only ever compared for
    /// equality to correlate messages within one attempt. Crate-internal wire
    /// plumbing for the message codec.
    #[must_use]
    const fn from_bytes(bytes: [u8; ATTEMPT_ID_LEN]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Returns the fixed 16-byte wire form. Crate-internal wire plumbing.
    #[must_use]
    const fn to_bytes(self) -> [u8; ATTEMPT_ID_LEN] {
        *self.0.as_bytes()
    }
}

impl fmt::Display for PairingAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

/// A bounded, protocol-defined reason a remote device declined a pairing request.
///
/// The set is deliberately small and closed. There is no free-form text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRejectionReason {
    /// No specific reason was provided.
    Unspecified,
    /// The remote device is busy with another pairing or transfer.
    Busy,
    /// A person on the remote device declined the request.
    Declined,
}

impl PairingRejectionReason {
    /// Returns the stable lowercase representation for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Busy => "busy",
            Self::Declined => "declined",
        }
    }

    const fn to_wire(self) -> u8 {
        match self {
            Self::Unspecified => REASON_UNSPECIFIED,
            Self::Busy => REASON_BUSY,
            Self::Declined => REASON_DECLINED,
        }
    }

    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            REASON_UNSPECIFIED => Some(Self::Unspecified),
            REASON_BUSY => Some(Self::Busy),
            REASON_DECLINED => Some(Self::Declined),
            _ => None,
        }
    }
}

impl fmt::Display for PairingRejectionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One bounded pairing-request-phase message.
///
/// Every message carries an explicit one-byte protocol version and the 16-byte
/// attempt identifier. These are the only messages this phase defines; the
/// authenticated handshake and the user-verification exchange are later issues.
///
/// This is crate-internal. Transports shuttle opaque bytes through
/// [`PairingRequest`] and [`PairingResponse`], which own encoding and
/// validation; adapters never see this enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PairingMessage {
    /// Initiator to responder: a request to begin pairing.
    Request {
        /// The initiator's attempt correlation identifier.
        attempt_id: PairingAttemptId,
    },
    /// Responder to initiator: the request may proceed to the authenticated stage.
    RequestAccepted {
        /// The attempt correlation identifier echoed from the request.
        attempt_id: PairingAttemptId,
    },
    /// Responder to initiator: the request is refused.
    RequestRejected {
        /// The attempt correlation identifier echoed from the request.
        attempt_id: PairingAttemptId,
        /// The bounded, protocol-defined reason.
        reason: PairingRejectionReason,
    },
}

impl PairingMessage {
    /// Builds a pairing request (initiator to responder).
    #[must_use]
    const fn request(attempt_id: PairingAttemptId) -> Self {
        Self::Request { attempt_id }
    }

    /// Builds a request-accepted reply (responder to initiator).
    #[must_use]
    const fn accepted(attempt_id: PairingAttemptId) -> Self {
        Self::RequestAccepted { attempt_id }
    }

    /// Builds a request-rejected reply (responder to initiator).
    #[must_use]
    const fn rejected(attempt_id: PairingAttemptId, reason: PairingRejectionReason) -> Self {
        Self::RequestRejected { attempt_id, reason }
    }

    /// Returns the attempt identifier this message correlates to.
    #[must_use]
    const fn attempt_id(&self) -> PairingAttemptId {
        match self {
            Self::Request { attempt_id }
            | Self::RequestAccepted { attempt_id }
            | Self::RequestRejected { attempt_id, .. } => *attempt_id,
        }
    }

    /// Encodes the message into its bounded wire form.
    #[must_use]
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_PAIRING_MESSAGE_BYTES);
        out.push(PAIRING_PROTOCOL_VERSION);
        match self {
            Self::Request { attempt_id } => {
                out.push(KIND_REQUEST);
                out.extend_from_slice(&attempt_id.to_bytes());
            }
            Self::RequestAccepted { attempt_id } => {
                out.push(KIND_REQUEST_ACCEPTED);
                out.extend_from_slice(&attempt_id.to_bytes());
            }
            Self::RequestRejected { attempt_id, reason } => {
                out.push(KIND_REQUEST_REJECTED);
                out.extend_from_slice(&attempt_id.to_bytes());
                out.push(reason.to_wire());
            }
        }
        out
    }

    /// Decodes bounded untrusted bytes into a pairing message.
    ///
    /// Length, protocol version, message kind, per-kind length, and any reason
    /// discriminant are all validated before a value is returned. Oversized,
    /// truncated, unsupported, or otherwise malformed input is rejected with a
    /// typed error that reveals only message structure.
    fn decode(bytes: &[u8]) -> Result<Self, PairingMessageError> {
        if bytes.len() < BASE_MESSAGE_LEN || bytes.len() > MAX_PAIRING_MESSAGE_BYTES {
            return Err(PairingMessageError::InvalidLength { len: bytes.len() });
        }
        let version = bytes[VERSION_OFFSET];
        if version != PAIRING_PROTOCOL_VERSION {
            return Err(PairingMessageError::UnsupportedVersion { version });
        }
        let kind = bytes[KIND_OFFSET];
        let mut attempt_id_bytes = [0_u8; ATTEMPT_ID_LEN];
        attempt_id_bytes
            .copy_from_slice(&bytes[ATTEMPT_ID_OFFSET..ATTEMPT_ID_OFFSET + ATTEMPT_ID_LEN]);
        let attempt_id = PairingAttemptId::from_bytes(attempt_id_bytes);

        match kind {
            KIND_REQUEST => {
                exact_len(bytes, BASE_MESSAGE_LEN, kind)?;
                Ok(Self::Request { attempt_id })
            }
            KIND_REQUEST_ACCEPTED => {
                exact_len(bytes, BASE_MESSAGE_LEN, kind)?;
                Ok(Self::RequestAccepted { attempt_id })
            }
            KIND_REQUEST_REJECTED => {
                exact_len(bytes, REJECTED_MESSAGE_LEN, kind)?;
                let raw = bytes[REASON_OFFSET];
                let reason = PairingRejectionReason::from_wire(raw)
                    .ok_or(PairingMessageError::UnknownRejectionReason { reason: raw })?;
                Ok(Self::RequestRejected { attempt_id, reason })
            }
            other => Err(PairingMessageError::UnknownMessageKind { kind: other }),
        }
    }
}

fn exact_len(bytes: &[u8], expected: usize, kind: u8) -> Result<(), PairingMessageError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(PairingMessageError::LengthKindMismatch {
            kind,
            len: bytes.len(),
        })
    }
}

/// A pairing-request-phase message is malformed or unsupported.
///
/// Values describe only message structure, never remote payload content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingMessageError {
    /// The encoded length is outside the range any valid message can occupy.
    InvalidLength {
        /// The rejected length.
        len: usize,
    },
    /// The message declares a protocol version this release does not implement.
    UnsupportedVersion {
        /// The unsupported version discriminant.
        version: u8,
    },
    /// The message-kind discriminant is not recognized.
    UnknownMessageKind {
        /// The unknown kind discriminant.
        kind: u8,
    },
    /// A rejection carries an unrecognized reason discriminant.
    UnknownRejectionReason {
        /// The unknown reason discriminant.
        reason: u8,
    },
    /// The encoded length is valid overall but wrong for the declared kind.
    LengthKindMismatch {
        /// The declared kind discriminant.
        kind: u8,
        /// The length that does not match that kind.
        len: usize,
    },
}

impl fmt::Display for PairingMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { len } => write!(
                formatter,
                "pairing message length {len} is outside the valid range \
                 {BASE_MESSAGE_LEN}..={MAX_PAIRING_MESSAGE_BYTES}"
            ),
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported pairing protocol version {version}")
            }
            Self::UnknownMessageKind { kind } => {
                write!(formatter, "unknown pairing message kind {kind}")
            }
            Self::UnknownRejectionReason { reason } => {
                write!(formatter, "unknown pairing rejection reason {reason}")
            }
            Self::LengthKindMismatch { kind, len } => write!(
                formatter,
                "pairing message kind {kind} does not permit length {len}"
            ),
        }
    }
}

impl Error for PairingMessageError {}

/// Why an initiator pairing attempt failed closed during the request phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRequestFailure {
    /// A remote message could not be decoded or was not supported.
    Protocol(PairingMessageError),
    /// A well-formed message arrived that the initiator must not act on in its
    /// current state, such as a request-role message or a response received
    /// before any request was sent through the transport.
    UnexpectedMessage,
    /// The caller reported that the pairing transport failed.
    TransportFailure,
}

impl fmt::Display for PairingRequestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(source) => {
                write!(formatter, "pairing request protocol failure: {source}")
            }
            Self::UnexpectedMessage => formatter.write_str(
                "received a pairing message that is not valid for the initiator in this state",
            ),
            Self::TransportFailure => {
                formatter.write_str("the pairing transport failed during the request phase")
            }
        }
    }
}

impl Error for PairingRequestFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(source) => Some(source),
            Self::UnexpectedMessage | Self::TransportFailure => None,
        }
    }
}

/// Why an input to the initiator state machine was a deterministic no-op.
///
/// An ignored input never changes state and never advances the attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRequestIgnored {
    /// The attempt is already in a terminal state; late input cannot revive it.
    AlreadyResolved,
    /// The request has already been marked sent.
    AlreadySent,
    /// A response arrived before the request was marked sent.
    NotAwaitingResponse,
    /// A response referenced a different attempt identifier.
    AttemptIdMismatch,
}

/// The initiator's position in the pairing-request phase.
///
/// `ReadyForNextPairingStage`, `Rejected`, `Cancelled`, `TimedOut`, and `Failed`
/// are terminal for this phase. None of them is trust: `ReadyForNextPairingStage`
/// only means the attempt may proceed to the next, authenticated stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRequestState {
    /// The attempt exists and the request message is ready to send.
    RequestCreated,
    /// The request was sent; the initiator is waiting for the remote response.
    AwaitingRemoteResponse,
    /// The remote accepted. The attempt may proceed to the authenticated stage.
    ReadyForNextPairingStage,
    /// The remote refused, with a bounded protocol reason. Terminal.
    Rejected(PairingRejectionReason),
    /// The local user cancelled the attempt. Terminal.
    Cancelled,
    /// The deadline elapsed before the remote responded. Terminal.
    TimedOut,
    /// The attempt failed closed. Terminal.
    Failed(PairingRequestFailure),
}

/// The outcome of applying one input to a [`PairingRequest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum PairingRequestEvent {
    /// The attempt is still in progress and within its deadline.
    Pending,
    /// The request was just marked sent; the initiator now awaits a response.
    AwaitingResponse,
    /// The remote accepted; the attempt may proceed to the authenticated stage.
    ReadyForNextPairingStage,
    /// The remote refused with a bounded reason.
    Rejected(PairingRejectionReason),
    /// The local user cancelled the attempt.
    Cancelled,
    /// The deadline elapsed.
    TimedOut,
    /// The attempt failed closed.
    Failed(PairingRequestFailure),
    /// The input was a deterministic no-op.
    Ignored(PairingRequestIgnored),
}

/// The initiator-side state machine for one pairing-request attempt.
///
/// The attempt is transient and in-memory. It owns only its correlation
/// identifier, its caller-supplied deadline, and its current state: no key,
/// fingerprint, trusted-peer record, storage handle, endpoint, hostname, or
/// discovery snapshot. It is never persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingRequest {
    attempt_id: PairingAttemptId,
    deadline: Duration,
    state: PairingRequestState,
}

impl PairingRequest {
    /// Begins an initiator-side pairing attempt from an explicit local action.
    ///
    /// This represents a user's explicit decision to pair with a device that is
    /// currently untrusted. Discovery code must never call it. It deliberately
    /// accepts no discovered-peer, endpoint, address, hostname, or
    /// discovery-key value: locating and addressing the target is the caller's
    /// responsibility and is not part of trust-relevant attempt state.
    ///
    /// The core generates a fresh transient correlation token for every call, so
    /// a caller cannot reuse one attempt's token for another: a retry is always
    /// a new, independent attempt. `deadline` is a value on the caller's
    /// monotonic timeline after which the attempt times out; this module chooses
    /// no timeout constant.
    #[must_use]
    pub fn initiate(deadline: Duration) -> Self {
        Self::with_attempt_id(PairingAttemptId::generate(), deadline)
    }

    /// Builds an attempt around a specific correlation token.
    ///
    /// Every attempt is created through here; [`initiate`](Self::initiate)
    /// generates the token, and tests pass a fixed one for determinism.
    #[must_use]
    const fn with_attempt_id(attempt_id: PairingAttemptId, deadline: Duration) -> Self {
        Self {
            attempt_id,
            deadline,
            state: PairingRequestState::RequestCreated,
        }
    }

    /// Returns this attempt's correlation identifier.
    #[must_use]
    pub const fn attempt_id(&self) -> PairingAttemptId {
        self.attempt_id
    }

    /// Returns the caller-supplied deadline for this attempt.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> PairingRequestState {
        self.state
    }

    /// Reports whether the attempt has reached a terminal state for this phase.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            PairingRequestState::ReadyForNextPairingStage
                | PairingRequestState::Rejected(_)
                | PairingRequestState::Cancelled
                | PairingRequestState::TimedOut
                | PairingRequestState::Failed(_)
        )
    }

    /// Reports whether the request phase completed successfully.
    ///
    /// A `true` result means only that the attempt may proceed to the next,
    /// authenticated pairing stage. It is not trust, authentication,
    /// verification, or transfer authorization.
    #[must_use]
    pub const fn is_ready_for_next_pairing_stage(&self) -> bool {
        matches!(self.state, PairingRequestState::ReadyForNextPairingStage)
    }

    /// Serializes the outbound pairing request while the attempt is still
    /// pending and within its deadline.
    ///
    /// While the attempt is pending this is idempotent: calling it any number of
    /// times returns the same bytes and never retransmits, moves toward a
    /// response, or starts a retry. Handing the bytes to a transport is the
    /// caller's action; call [`mark_request_sent`](Self::mark_request_sent) once
    /// that is done.
    ///
    /// It takes caller-supplied time so stale request bytes can never be mistaken
    /// for permission to continue: `now` at or after the deadline times the
    /// attempt out (state becomes [`PairingRequestState::TimedOut`]) and returns
    /// `None`. `None` is also returned once the request has been sent or the
    /// attempt is otherwise terminal; inspect [`state`](Self::state) to tell
    /// these apart. A retry after any terminal state requires a fresh
    /// [`initiate`](Self::initiate); re-reading old request bytes is not a retry.
    #[must_use]
    pub fn request_message(&mut self, now: Duration) -> Option<Vec<u8>> {
        if self.short_circuit(now).is_some() {
            return None;
        }
        match self.state {
            PairingRequestState::RequestCreated => {
                Some(PairingMessage::request(self.attempt_id).encode())
            }
            _ => None,
        }
    }

    /// Records that the caller handed the request to its transport for sending.
    ///
    /// This is a local handoff only; it does not mean the responder received the
    /// request. The initiator reaches readiness only on receiving a valid
    /// `request-accepted` reply.
    pub fn mark_request_sent(&mut self, now: Duration) -> PairingRequestEvent {
        if let Some(event) = self.short_circuit(now) {
            return event;
        }
        match self.state {
            PairingRequestState::RequestCreated => {
                self.state = PairingRequestState::AwaitingRemoteResponse;
                PairingRequestEvent::AwaitingResponse
            }
            _ => PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadySent),
        }
    }

    /// Applies one bounded, untrusted remote message to the attempt.
    ///
    /// The deadline is evaluated first, so a response that arrives at or after
    /// the deadline times the attempt out rather than resolving it. Malformed,
    /// unsupported, or role-inappropriate messages fail the attempt closed. A
    /// message for a different attempt identifier is ignored without disturbing
    /// this attempt. Once terminal, every message is an ignored no-op.
    pub fn handle_remote_message(&mut self, raw: &[u8], now: Duration) -> PairingRequestEvent {
        if let Some(event) = self.short_circuit(now) {
            return event;
        }
        let message = match PairingMessage::decode(raw) {
            Ok(message) => message,
            Err(error) => return self.fail(PairingRequestFailure::Protocol(error)),
        };
        if message.attempt_id() != self.attempt_id {
            return PairingRequestEvent::Ignored(PairingRequestIgnored::AttemptIdMismatch);
        }
        match message {
            PairingMessage::Request { .. } => self.fail(PairingRequestFailure::UnexpectedMessage),
            PairingMessage::RequestAccepted { .. } | PairingMessage::RequestRejected { .. }
                if self.state == PairingRequestState::RequestCreated =>
            {
                PairingRequestEvent::Ignored(PairingRequestIgnored::NotAwaitingResponse)
            }
            PairingMessage::RequestAccepted { .. } => {
                self.state = PairingRequestState::ReadyForNextPairingStage;
                PairingRequestEvent::ReadyForNextPairingStage
            }
            PairingMessage::RequestRejected { reason, .. } => {
                self.state = PairingRequestState::Rejected(reason);
                PairingRequestEvent::Rejected(reason)
            }
        }
    }

    /// Evaluates the deadline against caller-supplied time without other input.
    pub fn check_deadline(&mut self, now: Duration) -> PairingRequestEvent {
        self.short_circuit(now)
            .unwrap_or(PairingRequestEvent::Pending)
    }

    /// Cancels the attempt on an explicit local request.
    ///
    /// Cancellation is immediate and is not evaluated against the deadline: an
    /// explicit cancel of a non-terminal attempt is always recorded as
    /// [`PairingRequestState::Cancelled`].
    pub fn cancel(&mut self) -> PairingRequestEvent {
        if self.is_terminal() {
            return PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved);
        }
        self.state = PairingRequestState::Cancelled;
        PairingRequestEvent::Cancelled
    }

    /// Fails the attempt closed after the caller observes a transport failure.
    pub fn note_transport_failure(&mut self) -> PairingRequestEvent {
        if self.is_terminal() {
            return PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved);
        }
        self.fail(PairingRequestFailure::TransportFailure)
    }

    fn short_circuit(&mut self, now: Duration) -> Option<PairingRequestEvent> {
        if self.is_terminal() {
            return Some(PairingRequestEvent::Ignored(
                PairingRequestIgnored::AlreadyResolved,
            ));
        }
        if now >= self.deadline {
            self.state = PairingRequestState::TimedOut;
            return Some(PairingRequestEvent::TimedOut);
        }
        None
    }

    fn fail(&mut self, failure: PairingRequestFailure) -> PairingRequestEvent {
        self.state = PairingRequestState::Failed(failure);
        PairingRequestEvent::Failed(failure)
    }
}

/// A validated incoming pairing request could not start a responder attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingResponseError {
    /// The bytes were not a valid, supported pairing message.
    Protocol(PairingMessageError),
    /// The message decoded but is not a pairing request. The responder starts
    /// only from a request; an accept or reject reply cannot begin an attempt.
    NotARequest,
}

impl fmt::Display for PairingResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(source) => {
                write!(formatter, "invalid incoming pairing request: {source}")
            }
            Self::NotARequest => formatter.write_str(
                "the message is not a pairing request and cannot start a responder attempt",
            ),
        }
    }
}

impl Error for PairingResponseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(source) => Some(source),
            Self::NotARequest => None,
        }
    }
}

/// Why an input to the responder state machine was a deterministic no-op.
///
/// An ignored input never changes state and never advances the attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingResponseIgnored {
    /// The attempt is already in a terminal state; later input cannot revive it.
    AlreadyResolved,
    /// A local decision (accept or reject) has already been made.
    DecisionAlreadyMade,
    /// The request has not been accepted, so there is no reply to mark sent.
    NoAcceptedReply,
}

/// The responder's position in the pairing-request phase.
///
/// `ReadyForNextPairingStage`, `Rejected`, `Cancelled`, `TimedOut`, and `Failed`
/// are terminal. None of them is trust: `ReadyForNextPairingStage` only means
/// this side finished its local request-phase work and may proceed to the next,
/// authenticated stage. No state asserts that the initiator received anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingResponseState {
    /// A valid request is presented and awaits an explicit local decision.
    AwaitingDecision,
    /// The user accepted; the bounded acceptance reply was produced and still
    /// needs a successful local transport send before this side may proceed.
    AcceptedAwaitingSend,
    /// The caller reported the acceptance reply's local transport send
    /// succeeded. This responder finished its local request-phase obligations
    /// and may proceed to the authenticated stage; it does not assert the
    /// initiator received the reply.
    ReadyForNextPairingStage,
    /// The user rejected, with a bounded protocol reason. Terminal.
    Rejected(PairingRejectionReason),
    /// The local user cancelled, or the attempt was interrupted. Terminal.
    Cancelled,
    /// The deadline elapsed before the phase completed. Terminal.
    TimedOut,
    /// The attempt failed closed: the acceptance reply could not be sent through
    /// the local transport. Terminal.
    Failed,
}

/// The outcome of applying one input to a [`PairingResponse`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub enum PairingResponseEvent {
    /// The attempt is still awaiting a step and within its deadline.
    Pending,
    /// The user accepted. The bytes are the bounded `request-accepted` reply to
    /// send; call [`PairingResponse::mark_reply_sent`] once the local transport
    /// send of those bytes succeeds. Accepting is not trust: it is only local
    /// willingness to continue to the next authenticated stage.
    Accepted(Vec<u8>),
    /// The user rejected. The bytes are the bounded `request-rejected` reply to
    /// send; the attempt is already terminal whether or not the send succeeds or
    /// the initiator receives it.
    Rejected(Vec<u8>),
    /// The caller reported the acceptance reply's local transport send
    /// succeeded; this side may proceed to the next, authenticated pairing
    /// stage. Remote receipt is not claimed.
    ReadyForNextPairingStage,
    /// The local user cancelled or the attempt was interrupted.
    Cancelled,
    /// The deadline elapsed.
    TimedOut,
    /// The attempt failed closed (the acceptance reply could not be sent through
    /// the local transport).
    Failed,
    /// The input was a deterministic no-op.
    Ignored(PairingResponseIgnored),
}

/// The responder-side state machine for one incoming pairing request.
///
/// The attempt is transient and in-memory. It owns only the correlation
/// identifier echoed from the request, the caller-supplied deadline, and its
/// current state: no key, fingerprint, trusted-peer record, storage handle,
/// endpoint, hostname, discovery snapshot, or peer name. It is never persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingResponse {
    attempt_id: PairingAttemptId,
    deadline: Duration,
    state: PairingResponseState,
}

impl PairingResponse {
    /// Presents a validated incoming pairing request for an explicit local
    /// decision.
    ///
    /// `request` is untrusted network input: it is length-bounded, decoded,
    /// version-checked, and kind-checked before any responder state exists. Only
    /// a `request` message starts an attempt — an accept or reject reply yields
    /// [`PairingResponseError::NotARequest`], and malformed, oversized,
    /// truncated, or unsupported input yields [`PairingResponseError::Protocol`].
    /// The attempt's correlation identifier is taken from the validated request
    /// and echoed, unchanged, into the reply; it is never a peer identity, a
    /// credential, or trust.
    ///
    /// Discovery hints (display name, hostname, address, endpoint, discovery
    /// key) are routing/presentation metadata the caller holds separately; they
    /// are deliberately not part of responder state and cannot start an attempt.
    ///
    /// `deadline` is a value on the caller's monotonic timeline after which the
    /// attempt times out; this module chooses no timeout constant. Construction
    /// consults no clock and does not prove the deadline is still live: the first
    /// time-aware call ([`accept`](Self::accept), [`reject`](Self::reject),
    /// [`mark_reply_sent`](Self::mark_reply_sent), [`check_deadline`](Self::check_deadline))
    /// applies `now >= deadline` and times the attempt out, so an already-expired
    /// object can exist but can never decide or progress.
    pub fn from_request(request: &[u8], deadline: Duration) -> Result<Self, PairingResponseError> {
        match PairingMessage::decode(request).map_err(PairingResponseError::Protocol)? {
            PairingMessage::Request { attempt_id } => Ok(Self {
                attempt_id,
                deadline,
                state: PairingResponseState::AwaitingDecision,
            }),
            PairingMessage::RequestAccepted { .. } | PairingMessage::RequestRejected { .. } => {
                Err(PairingResponseError::NotARequest)
            }
        }
    }

    /// Returns the attempt correlation identifier echoed from the request.
    #[must_use]
    pub const fn attempt_id(&self) -> PairingAttemptId {
        self.attempt_id
    }

    /// Returns the caller-supplied deadline for this attempt.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> PairingResponseState {
        self.state
    }

    /// Reports whether the attempt has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            PairingResponseState::ReadyForNextPairingStage
                | PairingResponseState::Rejected(_)
                | PairingResponseState::Cancelled
                | PairingResponseState::TimedOut
                | PairingResponseState::Failed
        )
    }

    /// Reports whether the phase completed successfully.
    ///
    /// A `true` result means only that the caller reported the acceptance
    /// reply's local transport send succeeded and this side may proceed to the
    /// next, authenticated stage. It does not assert the initiator received the
    /// reply, and it is not trust, authentication, verification, or transfer
    /// authorization. If the initiator never receives the reply, later stages
    /// fail or time out safely.
    #[must_use]
    pub const fn is_ready_for_next_pairing_stage(&self) -> bool {
        matches!(self.state, PairingResponseState::ReadyForNextPairingStage)
    }

    /// Records an explicit local decision to accept the request.
    ///
    /// Valid only while awaiting the decision and within the deadline. It
    /// produces the bounded `request-accepted` reply (returned in
    /// [`PairingResponseEvent::Accepted`]) and moves to
    /// [`PairingResponseState::AcceptedAwaitingSend`]; the caller sends the
    /// reply through its transport and then, only if that local send succeeds,
    /// calls [`mark_reply_sent`](Self::mark_reply_sent). Acceptance is local
    /// willingness to continue: it creates no trust, persists nothing, and does
    /// not by itself mean the reply left this device.
    pub fn accept(&mut self, now: Duration) -> PairingResponseEvent {
        if let Some(event) = self.short_circuit(now) {
            return event;
        }
        match self.state {
            PairingResponseState::AwaitingDecision => {
                self.state = PairingResponseState::AcceptedAwaitingSend;
                PairingResponseEvent::Accepted(PairingMessage::accepted(self.attempt_id).encode())
            }
            _ => PairingResponseEvent::Ignored(PairingResponseIgnored::DecisionAlreadyMade),
        }
    }

    /// Records an explicit local decision to reject the request.
    ///
    /// Valid only while awaiting the decision and within the deadline. It
    /// produces the bounded `request-rejected` reply (returned in
    /// [`PairingResponseEvent::Rejected`]) with the given protocol reason and
    /// moves to the absorbing [`PairingResponseState::Rejected`] state.
    ///
    /// The rejection is final on this side the moment it is recorded: this
    /// responder will not proceed, the initiator stays untrusted, and no trust
    /// or partial state results. Sending the reply is best effort — if it is
    /// lost the initiator safely times out — so there is deliberately no
    /// rejection-send state to mirror acceptance.
    pub fn reject(
        &mut self,
        reason: PairingRejectionReason,
        now: Duration,
    ) -> PairingResponseEvent {
        if let Some(event) = self.short_circuit(now) {
            return event;
        }
        match self.state {
            PairingResponseState::AwaitingDecision => {
                self.state = PairingResponseState::Rejected(reason);
                PairingResponseEvent::Rejected(
                    PairingMessage::rejected(self.attempt_id, reason).encode(),
                )
            }
            _ => PairingResponseEvent::Ignored(PairingResponseIgnored::DecisionAlreadyMade),
        }
    }

    /// Records that the caller's local transport send of the acceptance reply
    /// completed successfully, per that transport's own contract.
    ///
    /// This is a local send/handoff outcome only. It does **not** mean the
    /// initiator received the reply, processed it, entered its next state, or
    /// acknowledged it; this issue adds no acknowledgement or delivery receipt.
    /// Valid only after [`accept`](Self::accept) and within the deadline; it
    /// moves to the terminal [`PairingResponseState::ReadyForNextPairingStage`],
    /// meaning this side has completed its local request-phase obligations.
    pub fn mark_reply_sent(&mut self, now: Duration) -> PairingResponseEvent {
        if let Some(event) = self.short_circuit(now) {
            return event;
        }
        match self.state {
            PairingResponseState::AcceptedAwaitingSend => {
                self.state = PairingResponseState::ReadyForNextPairingStage;
                PairingResponseEvent::ReadyForNextPairingStage
            }
            _ => PairingResponseEvent::Ignored(PairingResponseIgnored::NoAcceptedReply),
        }
    }

    /// Cancels or records an interruption of the attempt on an explicit local
    /// request.
    ///
    /// Cancellation and interruption are one outcome at this phase: both end the
    /// attempt with no trust and require a fresh incoming request to retry. It
    /// is immediate and not evaluated against the deadline.
    pub fn cancel(&mut self) -> PairingResponseEvent {
        if self.is_terminal() {
            return PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved);
        }
        self.state = PairingResponseState::Cancelled;
        PairingResponseEvent::Cancelled
    }

    /// Fails the attempt closed after the caller observes that the acceptance
    /// reply could not be sent through its transport.
    pub fn note_transport_failure(&mut self) -> PairingResponseEvent {
        if self.is_terminal() {
            return PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved);
        }
        self.state = PairingResponseState::Failed;
        PairingResponseEvent::Failed
    }

    /// Evaluates the deadline against caller-supplied time without other input.
    pub fn check_deadline(&mut self, now: Duration) -> PairingResponseEvent {
        self.short_circuit(now)
            .unwrap_or(PairingResponseEvent::Pending)
    }

    fn short_circuit(&mut self, now: Duration) -> Option<PairingResponseEvent> {
        if self.is_terminal() {
            return Some(PairingResponseEvent::Ignored(
                PairingResponseIgnored::AlreadyResolved,
            ));
        }
        if now >= self.deadline {
            self.state = PairingResponseState::TimedOut;
            return Some(PairingResponseEvent::TimedOut);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn id(byte: u8) -> PairingAttemptId {
        PairingAttemptId::from_bytes([byte; ATTEMPT_ID_LEN])
    }

    fn initiated() -> PairingRequest {
        PairingRequest::with_attempt_id(id(1), at(30))
    }

    fn awaiting() -> PairingRequest {
        let mut request = initiated();
        assert_eq!(
            request.mark_request_sent(at(0)),
            PairingRequestEvent::AwaitingResponse
        );
        request
    }

    #[test]
    fn initiation_is_explicit_and_takes_no_discovery_or_peer_types() {
        // The public constructor takes only a deadline and generates the
        // correlation token in core. No discovery type, and no caller-supplied
        // id, can flow in, so no discovery observation can start an attempt and
        // no caller can reuse a token.
        let _: fn(Duration) -> PairingRequest = PairingRequest::initiate;

        let request = PairingRequest::initiate(at(30));
        assert_eq!(request.state(), PairingRequestState::RequestCreated);
        assert!(!request.is_terminal());
        assert!(!request.is_ready_for_next_pairing_stage());
    }

    #[test]
    fn attempt_ids_round_trip_through_their_wire_form() {
        // Fixed bytes keep this deterministic: no assertion depends on two
        // generated identifiers differing.
        let fixed = id(7);
        assert_eq!(PairingAttemptId::from_bytes(fixed.to_bytes()), fixed);

        // A core-generated identifier also survives the same round trip.
        let generated = PairingRequest::initiate(at(30)).attempt_id();
        assert_eq!(
            PairingAttemptId::from_bytes(generated.to_bytes()),
            generated
        );
    }

    #[test]
    fn request_message_is_an_idempotent_view_available_only_before_sending() {
        let mut request = initiated();

        let first = request
            .request_message(at(1))
            .expect("the request is available before it is sent");
        assert!(first.len() <= MAX_PAIRING_MESSAGE_BYTES);
        assert_eq!(
            PairingMessage::decode(&first).unwrap(),
            PairingMessage::request(id(1))
        );

        // Repeated retrieval returns the same bytes and never advances the
        // attempt: no retransmission, no retry, no new attempt.
        let second = request.request_message(at(2)).expect("still pending");
        assert_eq!(first, second);
        assert_eq!(request.state(), PairingRequestState::RequestCreated);

        assert_eq!(
            request.mark_request_sent(at(3)),
            PairingRequestEvent::AwaitingResponse
        );
        assert_eq!(request.state(), PairingRequestState::AwaitingRemoteResponse);
        assert!(request.request_message(at(4)).is_none());
    }

    #[test]
    fn request_message_will_not_serve_bytes_for_an_expired_attempt() {
        let mut request = PairingRequest::with_attempt_id(id(1), at(10));

        assert!(request.request_message(at(10)).is_none());
        assert_eq!(request.state(), PairingRequestState::TimedOut);
        // A retry after expiry requires a fresh explicit initiation, not another
        // retrieval of the old request bytes.
        assert!(request.request_message(at(5)).is_none());
    }

    #[test]
    fn marking_the_request_sent_again_is_a_deterministic_noop() {
        let mut request = awaiting();

        assert_eq!(
            request.mark_request_sent(at(1)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadySent)
        );
        assert_eq!(request.state(), PairingRequestState::AwaitingRemoteResponse);
    }

    #[test]
    fn a_valid_acceptance_reaches_only_readiness_for_the_next_pairing_stage() {
        let mut request = awaiting();

        let event = request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(5));

        assert_eq!(event, PairingRequestEvent::ReadyForNextPairingStage);
        assert_eq!(
            request.state(),
            PairingRequestState::ReadyForNextPairingStage
        );
        assert!(request.is_ready_for_next_pairing_stage());
        assert!(request.is_terminal());
        // This is the most advanced state the phase can reach. There is no
        // `is_trusted`, `is_authenticated`, or `is_verified` accessor, no
        // trusted-peer type in this module, and nothing was persisted.
    }

    #[test]
    fn a_valid_rejection_is_terminal_untrusted_and_surfaces_its_reason() {
        for reason in [
            PairingRejectionReason::Unspecified,
            PairingRejectionReason::Busy,
            PairingRejectionReason::Declined,
        ] {
            let mut request = awaiting();

            let event = request
                .handle_remote_message(&PairingMessage::rejected(id(1), reason).encode(), at(5));

            assert_eq!(event, PairingRequestEvent::Rejected(reason));
            assert_eq!(request.state(), PairingRequestState::Rejected(reason));
            assert!(request.is_terminal());
            assert!(!request.is_ready_for_next_pairing_stage());
        }
    }

    #[test]
    fn a_retry_is_a_fresh_independent_attempt_that_shares_no_state() {
        let mut failed = awaiting();
        let _ = failed.handle_remote_message(
            &PairingMessage::rejected(id(1), PairingRejectionReason::Declined).encode(),
            at(1),
        );
        assert!(failed.is_terminal());

        // A retry is another explicit call to the production constructor. It is
        // a distinct object that starts clean; core owns its correlation token.
        let retry = PairingRequest::initiate(at(60));
        assert_eq!(retry.state(), PairingRequestState::RequestCreated);
        assert!(!retry.is_terminal());

        // No input revives the failed attempt, and none of its inputs touched
        // the retry object.
        assert_eq!(
            failed.mark_request_sent(at(2)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(
            failed.cancel(),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(
            failed.check_deadline(at(2)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(
            failed.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(2)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(
            failed.state(),
            PairingRequestState::Rejected(PairingRejectionReason::Declined)
        );
        assert_eq!(retry.state(), PairingRequestState::RequestCreated);
    }

    #[test]
    fn the_deadline_is_evaluated_only_against_caller_supplied_time() {
        let mut request = awaiting();

        assert_eq!(request.check_deadline(at(29)), PairingRequestEvent::Pending);
        assert_eq!(request.state(), PairingRequestState::AwaitingRemoteResponse);

        assert_eq!(
            request.check_deadline(at(30)),
            PairingRequestEvent::TimedOut
        );
        assert_eq!(request.state(), PairingRequestState::TimedOut);

        // Repeated checks, even with an earlier time, stay a deterministic no-op.
        for now in [at(31), at(1)] {
            assert_eq!(
                request.check_deadline(now),
                PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
            );
            assert_eq!(request.state(), PairingRequestState::TimedOut);
        }
    }

    #[test]
    fn a_late_acceptance_at_or_after_the_deadline_cannot_revive_the_attempt() {
        let mut request = awaiting();
        let accepted = PairingMessage::accepted(id(1)).encode();

        assert_eq!(
            request.handle_remote_message(&accepted, at(30)),
            PairingRequestEvent::TimedOut
        );
        assert_eq!(request.state(), PairingRequestState::TimedOut);

        assert_eq!(
            request.handle_remote_message(&accepted, at(31)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(request.state(), PairingRequestState::TimedOut);
    }

    #[test]
    fn timeout_can_occur_before_the_request_is_sent() {
        let mut request = PairingRequest::with_attempt_id(id(1), at(10));

        assert_eq!(
            request.mark_request_sent(at(10)),
            PairingRequestEvent::TimedOut
        );
        assert_eq!(request.state(), PairingRequestState::TimedOut);
        assert!(request.request_message(at(11)).is_none());
    }

    #[test]
    fn cancellation_is_explicit_and_terminal_from_every_in_progress_state() {
        let mut created = initiated();
        assert_eq!(created.cancel(), PairingRequestEvent::Cancelled);
        assert_eq!(created.state(), PairingRequestState::Cancelled);

        let mut waiting = awaiting();
        assert_eq!(waiting.cancel(), PairingRequestEvent::Cancelled);
        assert_eq!(waiting.state(), PairingRequestState::Cancelled);
    }

    #[test]
    fn repeated_cancellation_and_late_responses_after_cancellation_are_ignored() {
        let mut request = awaiting();
        let _ = request.cancel();

        assert_eq!(
            request.cancel(),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        for message in [
            PairingMessage::accepted(id(1)),
            PairingMessage::rejected(id(1), PairingRejectionReason::Busy),
        ] {
            assert_eq!(
                request.handle_remote_message(&message.encode(), at(2)),
                PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
            );
        }
        assert_eq!(request.state(), PairingRequestState::Cancelled);
    }

    #[test]
    fn a_transport_failure_fails_the_attempt_closed() {
        let mut request = awaiting();

        assert_eq!(
            request.note_transport_failure(),
            PairingRequestEvent::Failed(PairingRequestFailure::TransportFailure)
        );
        assert!(request.is_terminal());
        assert!(!request.is_ready_for_next_pairing_stage());
        assert_eq!(
            request.note_transport_failure(),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
    }

    #[test]
    fn an_early_response_is_ignored_and_is_never_cached_or_replayed() {
        let mut request = initiated();

        // An acceptance that arrives before the request was marked sent.
        assert_eq!(
            request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(1)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::NotAwaitingResponse)
        );
        assert_eq!(request.state(), PairingRequestState::RequestCreated);

        assert_eq!(
            request.mark_request_sent(at(2)),
            PairingRequestEvent::AwaitingResponse
        );

        // The early acceptance was not buffered: the attempt still waits, and it
        // is the next properly ordered response that decides the outcome. Here a
        // rejection wins, proving the earlier acceptance was discarded.
        assert_eq!(request.check_deadline(at(3)), PairingRequestEvent::Pending);
        assert_eq!(
            request.handle_remote_message(
                &PairingMessage::rejected(id(1), PairingRejectionReason::Declined).encode(),
                at(4),
            ),
            PairingRequestEvent::Rejected(PairingRejectionReason::Declined)
        );
        assert_eq!(
            request.state(),
            PairingRequestState::Rejected(PairingRejectionReason::Declined)
        );
    }

    #[test]
    fn a_properly_ordered_response_still_succeeds_after_an_early_response() {
        let mut request = initiated();
        let _ = request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(1));
        assert_eq!(
            request.mark_request_sent(at(2)),
            PairingRequestEvent::AwaitingResponse
        );

        assert_eq!(
            request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(3)),
            PairingRequestEvent::ReadyForNextPairingStage
        );
    }

    #[test]
    fn a_request_role_message_received_by_the_initiator_fails_closed() {
        let mut request = awaiting();

        assert_eq!(
            request.handle_remote_message(&PairingMessage::request(id(1)).encode(), at(1)),
            PairingRequestEvent::Failed(PairingRequestFailure::UnexpectedMessage)
        );
        assert_eq!(
            request.state(),
            PairingRequestState::Failed(PairingRequestFailure::UnexpectedMessage)
        );
    }

    #[test]
    fn a_response_for_a_different_attempt_is_ignored_without_disturbing_the_attempt() {
        let mut request = awaiting();

        assert_eq!(
            request.handle_remote_message(&PairingMessage::accepted(id(2)).encode(), at(1)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AttemptIdMismatch)
        );
        assert_eq!(request.state(), PairingRequestState::AwaitingRemoteResponse);

        assert_eq!(
            request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(2)),
            PairingRequestEvent::ReadyForNextPairingStage
        );
    }

    #[test]
    fn duplicate_and_conflicting_responses_after_resolution_are_ignored() {
        let mut request = awaiting();
        let _ = request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(1));

        for message in [
            PairingMessage::accepted(id(1)),
            PairingMessage::rejected(id(1), PairingRejectionReason::Declined),
        ] {
            assert_eq!(
                request.handle_remote_message(&message.encode(), at(2)),
                PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
            );
        }
        assert_eq!(
            request.state(),
            PairingRequestState::ReadyForNextPairingStage
        );
    }

    #[test]
    fn messages_round_trip_through_their_bounded_encoding() {
        let cases = [
            PairingMessage::request(id(3)),
            PairingMessage::accepted(id(3)),
            PairingMessage::rejected(id(3), PairingRejectionReason::Unspecified),
            PairingMessage::rejected(id(3), PairingRejectionReason::Busy),
            PairingMessage::rejected(id(3), PairingRejectionReason::Declined),
        ];

        for message in cases {
            let encoded = message.encode();
            assert!(encoded.len() <= MAX_PAIRING_MESSAGE_BYTES);
            assert_eq!(encoded[VERSION_OFFSET], PAIRING_PROTOCOL_VERSION);

            let decoded = PairingMessage::decode(&encoded).unwrap();
            assert_eq!(decoded, message);
            assert_eq!(decoded.attempt_id(), id(3));
        }
    }

    #[test]
    fn decode_rejects_input_outside_the_length_bounds() {
        for len in [
            0_usize,
            1,
            BASE_MESSAGE_LEN - 1,
            MAX_PAIRING_MESSAGE_BYTES + 1,
            128,
        ] {
            let bytes = vec![PAIRING_PROTOCOL_VERSION; len];
            assert_eq!(
                PairingMessage::decode(&bytes).unwrap_err(),
                PairingMessageError::InvalidLength { len }
            );
        }
    }

    #[test]
    fn decode_accepts_messages_at_the_exact_length_limits() {
        let request = PairingMessage::request(id(1)).encode();
        assert_eq!(request.len(), BASE_MESSAGE_LEN);
        assert!(PairingMessage::decode(&request).is_ok());

        let rejection = PairingMessage::rejected(id(1), PairingRejectionReason::Declined).encode();
        assert_eq!(rejection.len(), REJECTED_MESSAGE_LEN);
        assert_eq!(rejection.len(), MAX_PAIRING_MESSAGE_BYTES);
        assert!(PairingMessage::decode(&rejection).is_ok());
    }

    #[test]
    fn decode_rejects_an_unsupported_protocol_version() {
        let mut bytes = PairingMessage::request(id(1)).encode();
        bytes[VERSION_OFFSET] = PAIRING_PROTOCOL_VERSION + 1;

        assert_eq!(
            PairingMessage::decode(&bytes).unwrap_err(),
            PairingMessageError::UnsupportedVersion {
                version: PAIRING_PROTOCOL_VERSION + 1
            }
        );
    }

    #[test]
    fn decode_rejects_an_unknown_message_kind() {
        for kind in [0_u8, 4, 200] {
            let mut bytes = PairingMessage::request(id(1)).encode();
            bytes[KIND_OFFSET] = kind;

            assert_eq!(
                PairingMessage::decode(&bytes).unwrap_err(),
                PairingMessageError::UnknownMessageKind { kind }
            );
        }
    }

    #[test]
    fn decode_rejects_an_unknown_rejection_reason() {
        let mut bytes = PairingMessage::rejected(id(1), PairingRejectionReason::Busy).encode();
        bytes[REASON_OFFSET] = 250;

        assert_eq!(
            PairingMessage::decode(&bytes).unwrap_err(),
            PairingMessageError::UnknownRejectionReason { reason: 250 }
        );
    }

    #[test]
    fn decode_rejects_a_length_that_disagrees_with_the_message_kind() {
        let mut long_request = PairingMessage::request(id(1)).encode();
        long_request.push(0);
        assert_eq!(
            PairingMessage::decode(&long_request).unwrap_err(),
            PairingMessageError::LengthKindMismatch {
                kind: KIND_REQUEST,
                len: REJECTED_MESSAGE_LEN,
            }
        );

        let full = PairingMessage::rejected(id(1), PairingRejectionReason::Busy).encode();
        assert_eq!(
            PairingMessage::decode(&full[..BASE_MESSAGE_LEN]).unwrap_err(),
            PairingMessageError::LengthKindMismatch {
                kind: KIND_REQUEST_REJECTED,
                len: BASE_MESSAGE_LEN,
            }
        );
    }

    #[test]
    fn a_malformed_remote_message_fails_the_attempt_closed() {
        let mut request = awaiting();

        assert_eq!(
            request.handle_remote_message(&[0xff, 0xff, 0xff], at(1)),
            PairingRequestEvent::Failed(PairingRequestFailure::Protocol(
                PairingMessageError::InvalidLength { len: 3 }
            ))
        );
        assert!(request.is_terminal());
    }

    #[test]
    fn an_unsupported_version_from_the_remote_fails_the_attempt_closed() {
        let mut request = awaiting();
        let mut bytes = PairingMessage::accepted(id(1)).encode();
        bytes[VERSION_OFFSET] = 9;

        assert_eq!(
            request.handle_remote_message(&bytes, at(1)),
            PairingRequestEvent::Failed(PairingRequestFailure::Protocol(
                PairingMessageError::UnsupportedVersion { version: 9 }
            ))
        );
    }

    #[test]
    fn the_success_terminal_carries_no_peer_key_or_record_data() {
        // The trust boundary is enforced by the API shape, the fields the type
        // owns (a correlation id, a deadline, a state discriminant), the absence
        // of any persistence, crypto, or discovery dependency, and the behaviour
        // below -- not by any size or reflection trick.
        let mut request = awaiting();
        let _ = request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(1));

        // The strongest positive signal the phase can give is a unit variant.
        // There is no `is_trusted`/`is_authenticated`/`is_verified` accessor and
        // no payload to carry a peer, key, fingerprint, or record.
        assert_eq!(
            request.state(),
            PairingRequestState::ReadyForNextPairingStage
        );
        assert!(request.is_ready_for_next_pairing_stage());

        // Reaching success starts nothing else: the attempt just sits terminal
        // and every further input is an ignored no-op.
        assert_eq!(
            request.mark_request_sent(at(2)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(
            request.handle_remote_message(&PairingMessage::accepted(id(1)).encode(), at(3)),
            PairingRequestEvent::Ignored(PairingRequestIgnored::AlreadyResolved)
        );
        assert_eq!(request.request_message(at(4)), None);
    }

    #[test]
    fn failure_categories_expose_their_typed_source() {
        let failure =
            PairingRequestFailure::Protocol(PairingMessageError::UnsupportedVersion { version: 2 });
        assert!(failure.source().is_some());
        assert!(PairingRequestFailure::TransportFailure.source().is_none());
        assert!(!failure.to_string().is_empty());
    }

    // ----- responder side -----

    fn request_bytes(attempt: u8) -> Vec<u8> {
        PairingMessage::request(id(attempt)).encode()
    }

    fn presented() -> PairingResponse {
        let responder = PairingResponse::from_request(&request_bytes(1), at(30)).unwrap();
        assert_eq!(responder.state(), PairingResponseState::AwaitingDecision);
        responder
    }

    fn decoded_reply(event: &PairingResponseEvent) -> PairingMessage {
        let bytes = match event {
            PairingResponseEvent::Accepted(bytes) | PairingResponseEvent::Rejected(bytes) => bytes,
            other => panic!("expected a reply-bearing event, got {other:?}"),
        };
        assert!(bytes.len() <= MAX_PAIRING_MESSAGE_BYTES);
        PairingMessage::decode(bytes).unwrap()
    }

    #[test]
    fn a_valid_request_creates_the_presentation_state_and_nothing_more() {
        let responder = presented();

        assert_eq!(responder.attempt_id(), id(1));
        assert_eq!(responder.state(), PairingResponseState::AwaitingDecision);
        assert!(!responder.is_terminal());
        assert!(!responder.is_ready_for_next_pairing_stage());
        // No automatic acceptance: presentation requires an explicit local
        // decision, and there is no trusted/authenticated/verified accessor.
    }

    #[test]
    fn the_responder_starts_only_from_a_request_message() {
        // A reply message cannot begin responder state.
        for reply in [
            PairingMessage::accepted(id(1)).encode(),
            PairingMessage::rejected(id(1), PairingRejectionReason::Busy).encode(),
        ] {
            assert_eq!(
                PairingResponse::from_request(&reply, at(30)).unwrap_err(),
                PairingResponseError::NotARequest
            );
        }
    }

    #[test]
    fn malformed_oversized_and_unsupported_request_bytes_cannot_create_state() {
        // Out of length bounds.
        for bytes in [
            vec![],
            vec![1_u8; 3],
            vec![1_u8; MAX_PAIRING_MESSAGE_BYTES + 1],
        ] {
            assert!(matches!(
                PairingResponse::from_request(&bytes, at(30)).unwrap_err(),
                PairingResponseError::Protocol(_)
            ));
        }

        // Unsupported version.
        let mut wrong_version = request_bytes(1);
        wrong_version[VERSION_OFFSET] = PAIRING_PROTOCOL_VERSION + 1;
        assert_eq!(
            PairingResponse::from_request(&wrong_version, at(30)).unwrap_err(),
            PairingResponseError::Protocol(PairingMessageError::UnsupportedVersion {
                version: PAIRING_PROTOCOL_VERSION + 1
            })
        );

        // Unknown kind.
        let mut wrong_kind = request_bytes(1);
        wrong_kind[KIND_OFFSET] = 0;
        assert_eq!(
            PairingResponse::from_request(&wrong_kind, at(30)).unwrap_err(),
            PairingResponseError::Protocol(PairingMessageError::UnknownMessageKind { kind: 0 })
        );
    }

    #[test]
    fn explicit_acceptance_reaches_readiness_only_after_a_successful_local_send() {
        let mut responder = presented();

        // Local accept alone is not readiness: it produces the reply and waits
        // for a successful local transport send.
        let event = responder.accept(at(5));
        assert_eq!(
            decoded_reply(&event),
            PairingMessage::accepted(id(1)),
            "the acceptance reply echoes the request attempt id"
        );
        assert_eq!(
            responder.state(),
            PairingResponseState::AcceptedAwaitingSend
        );
        assert!(!responder.is_terminal());
        assert!(!responder.is_ready_for_next_pairing_stage());

        // Readiness requires the explicit successful-local-send notification.
        assert_eq!(
            responder.mark_reply_sent(at(6)),
            PairingResponseEvent::ReadyForNextPairingStage
        );
        assert_eq!(
            responder.state(),
            PairingResponseState::ReadyForNextPairingStage
        );
        assert!(responder.is_ready_for_next_pairing_stage());
        assert!(responder.is_terminal());
        // ReadyForNextPairingStage carries no payload: no trusted record, key,
        // fingerprint, or remote-delivery acknowledgement. It is only permission
        // for this side to proceed to the authenticated stage; the initiator may
        // never have received the reply, in which case later stages fail or time
        // out safely.
    }

    #[test]
    fn explicit_rejection_produces_the_reply_and_is_immediately_terminal() {
        for reason in [
            PairingRejectionReason::Unspecified,
            PairingRejectionReason::Busy,
            PairingRejectionReason::Declined,
        ] {
            let mut responder = presented();

            let event = responder.reject(reason, at(5));
            assert_eq!(
                decoded_reply(&event),
                PairingMessage::rejected(id(1), reason),
                "the rejection reply echoes the request attempt id and carries the typed reason"
            );
            assert_eq!(responder.state(), PairingResponseState::Rejected(reason));
            assert!(responder.is_terminal());
            assert!(!responder.is_ready_for_next_pairing_stage());
        }
    }

    #[test]
    fn there_is_no_automatic_acceptance_from_presentation_or_time() {
        let mut responder = presented();

        // Merely checking the deadline never accepts.
        assert_eq!(
            responder.check_deadline(at(1)),
            PairingResponseEvent::Pending
        );
        assert_eq!(
            responder.check_deadline(at(29)),
            PairingResponseEvent::Pending
        );
        assert_eq!(responder.state(), PairingResponseState::AwaitingDecision);
        assert!(!responder.is_ready_for_next_pairing_stage());
    }

    #[test]
    fn the_responder_never_mints_a_replacement_attempt_id() {
        let mut accepting = PairingResponse::from_request(&request_bytes(9), at(30)).unwrap();
        let mut rejecting = PairingResponse::from_request(&request_bytes(9), at(30)).unwrap();

        assert_eq!(accepting.attempt_id(), id(9));
        assert_eq!(decoded_reply(&accepting.accept(at(1))).attempt_id(), id(9));
        assert_eq!(
            decoded_reply(&rejecting.reject(PairingRejectionReason::Declined, at(1))).attempt_id(),
            id(9)
        );
    }

    #[test]
    fn the_responder_deadline_is_evaluated_only_against_caller_supplied_time() {
        let mut responder = presented();

        assert_eq!(
            responder.check_deadline(at(29)),
            PairingResponseEvent::Pending
        );
        assert_eq!(responder.state(), PairingResponseState::AwaitingDecision);

        assert_eq!(
            responder.check_deadline(at(30)),
            PairingResponseEvent::TimedOut
        );
        assert_eq!(responder.state(), PairingResponseState::TimedOut);

        for now in [at(31), at(1)] {
            assert_eq!(
                responder.check_deadline(now),
                PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
            );
        }
    }

    #[test]
    fn acceptance_at_or_after_the_deadline_times_out_instead_of_accepting() {
        let mut responder = presented();

        assert_eq!(responder.accept(at(30)), PairingResponseEvent::TimedOut);
        assert_eq!(responder.state(), PairingResponseState::TimedOut);
        assert_eq!(
            responder.accept(at(31)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
        );
    }

    #[test]
    fn a_reply_cannot_be_marked_sent_once_the_deadline_has_passed() {
        let mut responder = presented();
        assert!(matches!(
            responder.accept(at(5)),
            PairingResponseEvent::Accepted(_)
        ));

        assert_eq!(
            responder.mark_reply_sent(at(30)),
            PairingResponseEvent::TimedOut
        );
        assert_eq!(responder.state(), PairingResponseState::TimedOut);
    }

    #[test]
    fn rejection_after_the_deadline_times_out() {
        let mut responder = presented();
        assert_eq!(
            responder.reject(PairingRejectionReason::Declined, at(30)),
            PairingResponseEvent::TimedOut
        );
        assert_eq!(responder.state(), PairingResponseState::TimedOut);
    }

    #[test]
    fn cancellation_ends_the_attempt_and_blocks_any_later_decision() {
        // From the presentation state.
        let mut from_presentation = presented();
        assert_eq!(from_presentation.cancel(), PairingResponseEvent::Cancelled);
        assert_eq!(from_presentation.state(), PairingResponseState::Cancelled);

        // From after acceptance but before the reply's local send (an interruption).
        let mut after_accept = presented();
        let _ = after_accept.accept(at(1));
        assert_eq!(after_accept.cancel(), PairingResponseEvent::Cancelled);
        assert_eq!(after_accept.state(), PairingResponseState::Cancelled);

        // No later decision can revive either.
        for mut responder in [from_presentation, after_accept] {
            assert_eq!(
                responder.cancel(),
                PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
            );
            assert_eq!(
                responder.accept(at(2)),
                PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
            );
            assert_eq!(
                responder.reject(PairingRejectionReason::Busy, at(2)),
                PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
            );
            assert_eq!(
                responder.mark_reply_sent(at(2)),
                PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
            );
        }
    }

    #[test]
    fn a_transport_failure_fails_the_responder_attempt_closed() {
        let mut responder = presented();
        let _ = responder.accept(at(1));

        assert_eq!(
            responder.note_transport_failure(),
            PairingResponseEvent::Failed
        );
        assert!(responder.is_terminal());
        assert!(!responder.is_ready_for_next_pairing_stage());
        assert_eq!(
            responder.mark_reply_sent(at(2)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
        );
    }

    #[test]
    fn duplicate_and_conflicting_local_decisions_are_deterministic_no_ops() {
        // Accept twice: the second accept does not re-emit a reply.
        let mut accept_twice = presented();
        assert!(matches!(
            accept_twice.accept(at(1)),
            PairingResponseEvent::Accepted(_)
        ));
        assert_eq!(
            accept_twice.accept(at(1)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::DecisionAlreadyMade)
        );
        assert_eq!(
            accept_twice.state(),
            PairingResponseState::AcceptedAwaitingSend
        );

        // Reject after accept: the acceptance stands.
        assert_eq!(
            accept_twice.reject(PairingRejectionReason::Declined, at(1)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::DecisionAlreadyMade)
        );
        assert_eq!(
            accept_twice.state(),
            PairingResponseState::AcceptedAwaitingSend
        );

        // Reject twice, then accept after reject.
        let mut reject_twice = presented();
        assert!(matches!(
            reject_twice.reject(PairingRejectionReason::Busy, at(1)),
            PairingResponseEvent::Rejected(_)
        ));
        assert_eq!(
            reject_twice.reject(PairingRejectionReason::Busy, at(1)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
        );
        assert_eq!(
            reject_twice.accept(at(1)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
        );
        assert_eq!(
            reject_twice.state(),
            PairingResponseState::Rejected(PairingRejectionReason::Busy)
        );
    }

    #[test]
    fn marking_a_reply_sent_before_acceptance_is_a_no_op() {
        let mut responder = presented();
        assert_eq!(
            responder.mark_reply_sent(at(1)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::NoAcceptedReply)
        );
        assert_eq!(responder.state(), PairingResponseState::AwaitingDecision);
    }

    #[test]
    fn readiness_is_absorbing_and_carries_no_trust_payload() {
        let mut responder = presented();
        let _ = responder.accept(at(1));
        assert_eq!(
            responder.mark_reply_sent(at(2)),
            PairingResponseEvent::ReadyForNextPairingStage
        );

        // The success terminal is a unit variant. Every later input is a no-op.
        for event in [
            responder.accept(at(3)),
            responder.reject(PairingRejectionReason::Declined, at(3)),
            responder.mark_reply_sent(at(3)),
            responder.cancel(),
            responder.note_transport_failure(),
            responder.check_deadline(at(3)),
        ] {
            assert_eq!(
                event,
                PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
            );
        }
        assert_eq!(
            responder.state(),
            PairingResponseState::ReadyForNextPairingStage
        );
    }

    #[test]
    fn a_responder_retry_requires_a_fresh_request_and_a_new_decision() {
        let mut done = presented();
        assert!(matches!(
            done.reject(PairingRejectionReason::Declined, at(1)),
            PairingResponseEvent::Rejected(_)
        ));
        assert!(done.is_terminal());

        // A retry is a brand-new responder object built from a fresh incoming
        // request. It shares no state and needs its own explicit decision.
        let fresh = PairingResponse::from_request(&request_bytes(2), at(60)).unwrap();
        assert_eq!(fresh.state(), PairingResponseState::AwaitingDecision);
        assert!(!fresh.is_terminal());

        // The old object stays terminal forever.
        assert_eq!(
            done.accept(at(2)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
        );
        assert_eq!(
            done.state(),
            PairingResponseState::Rejected(PairingRejectionReason::Declined)
        );
        assert_eq!(fresh.state(), PairingResponseState::AwaitingDecision);
    }

    #[test]
    fn receiving_a_request_and_accepting_it_are_both_distinct_from_trust() {
        // Receiving: presentation state only, no trust signal.
        let mut responder = presented();
        assert!(!responder.is_ready_for_next_pairing_stage());

        // Accepting: local willingness only. Still not ready, not terminal, and
        // the reply has not been sent.
        let _ = responder.accept(at(1));
        assert!(!responder.is_ready_for_next_pairing_stage());
        assert!(!responder.is_terminal());

        // Success: only readiness for the authenticated stage. The strongest
        // positive signal is a bool from a unit state; the type has no
        // fingerprint, key, verified name, trusted-peer record, or remote-
        // delivery acknowledgement, and no accessor that could expose one.
        let _ = responder.mark_reply_sent(at(2));
        assert!(responder.is_ready_for_next_pairing_stage());
    }

    #[test]
    fn a_timeout_before_the_successful_send_notification_prevents_readiness() {
        let mut responder = presented();
        let _ = responder.accept(at(1));

        // The deadline passes while the caller is still trying to send the reply.
        assert_eq!(
            responder.check_deadline(at(30)),
            PairingResponseEvent::TimedOut
        );
        assert_eq!(responder.state(), PairingResponseState::TimedOut);
        assert!(!responder.is_ready_for_next_pairing_stage());

        // A later successful-send notification cannot revive it.
        assert_eq!(
            responder.mark_reply_sent(at(31)),
            PairingResponseEvent::Ignored(PairingResponseIgnored::AlreadyResolved)
        );
        assert!(!responder.is_ready_for_next_pairing_stage());
    }

    #[test]
    fn responder_error_categories_expose_their_typed_source() {
        let protocol =
            PairingResponseError::Protocol(PairingMessageError::InvalidLength { len: 0 });
        assert!(protocol.source().is_some());
        assert!(!protocol.to_string().is_empty());
        assert!(PairingResponseError::NotARequest.source().is_none());
    }
}
