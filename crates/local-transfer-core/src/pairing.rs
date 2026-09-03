//! Initiator-side pairing-request phase.
//!
//! This module implements only the first phase of a pairing attempt: an
//! explicit, local decision to request pairing from a currently untrusted
//! device, the small bounded messages that phase exchanges, and the
//! deterministic initiator state machine that tracks it.
//!
//! Reaching the successful terminal state,
//! [`PairingRequestState::ReadyForNextPairingStage`], means only that the
//! attempt may proceed to the next, authenticated pairing stage. It never means
//! the remote device is trusted, authenticated, verified, or authorized for any
//! transfer. There is no trusted-peer record anywhere in this module, nothing
//! here is persisted, and no cryptography is performed. The authenticated key
//! agreement and the user-verifiable step are separate issues; see
//! `docs/trust.md` and `docs/protocol.md`.
//!
//! The state machine reads no clock: callers supply monotonic [`Duration`]
//! values and an explicit deadline. It never retries on its own. A retry is a
//! brand-new [`PairingRequest`] created by another explicit initiation, sharing
//! no state with the previous attempt.

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
/// This is crate-internal: the initiator's transport shuttles opaque bytes
/// through [`PairingRequest::request_message`] and
/// [`PairingRequest::handle_remote_message`], which own encoding and validation.
/// The message type becomes part of the public API when the responder side
/// (issue #19) needs it.
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
    /// Builds a pairing request for an attempt.
    #[must_use]
    const fn request(attempt_id: PairingAttemptId) -> Self {
        Self::Request { attempt_id }
    }

    /// Builds a request-accepted message. The initiator only ever receives this
    /// message, so the constructor exists for tests until the responder side
    /// (issue #19) needs it.
    #[cfg(test)]
    #[must_use]
    const fn accepted(attempt_id: PairingAttemptId) -> Self {
        Self::RequestAccepted { attempt_id }
    }

    /// Builds a request-rejected message. The initiator only ever receives this
    /// message, so the constructor exists for tests until the responder side
    /// (issue #19) needs it.
    #[cfg(test)]
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

    /// Records that the request was handed to the transport for delivery.
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
}
