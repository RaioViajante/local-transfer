//! `local-transfer discover`: observe transient, unauthenticated nearby devices.
//!
//! This module is a thin adapter over the `local-transfer-core` discovery stack.
//! It drives a browser session into [`DiscoveredPeerState`], asks core to expire
//! stale entries when requested, and renders the resulting snapshot and lifecycle
//! transitions. It contains no discovery parsing, compatibility, coalescing,
//! expiry, or identity logic of its own.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use local_transfer_core::browser::{DiscoveredPeer, DiscoveryBrowser, DiscoveryBrowserError};
use local_transfer_core::discovered_peers::{
    DiscoveredPeerNoopReason, DiscoveredPeerRemovalReason, DiscoveredPeerState,
    DiscoveredPeerTransition,
};
use local_transfer_core::discovery::DiscoveryPlatformHint;

/// Interval between backend polls while the observation window is open.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Standing reminder that discovery never establishes trust or identity.
const ADVISORY_NOTICE: &str = "Discovery is advisory and unauthenticated: a device listed here is \
currently advertising on the local network but is not paired, trusted, or authenticated, and its \
name and addresses are unverified hints.";

/// Arguments for `local-transfer discover`.
#[derive(Debug, PartialEq, clap::Args)]
pub(crate) struct DiscoverArgs {
    /// Print each discovery lifecycle event before the device list.
    #[arg(long)]
    pub(crate) events: bool,

    /// Seconds to observe the local network before printing results.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 3,
        value_parser = clap::value_parser!(u64).range(1..=60),
    )]
    pub(crate) window: u64,

    /// Ask core to drop devices not re-observed within this many seconds.
    ///
    /// Omitted, devices are never expired during the pass; explicit removals
    /// still apply. The staleness rule itself lives in `local-transfer-core`.
    #[arg(
        long,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=3600),
    )]
    pub(crate) stale_after: Option<u64>,
}

/// A discovery command failure that keeps infrastructure detail behind the boundary.
#[derive(Debug)]
pub(crate) enum DiscoveryCliError {
    /// The interrupt handler could not be installed.
    Interrupt(io::Error),
    /// Discovery could not be started.
    Start(DiscoveryBrowserError),
    /// Discovery resources could not be stopped cleanly.
    Shutdown(DiscoveryBrowserError),
    /// Command output could not be written.
    Output(io::Error),
}

impl fmt::Display for DiscoveryCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupt(source) => {
                write!(
                    formatter,
                    "failed to install the interrupt handler: {source}"
                )
            }
            Self::Start(source) => write!(formatter, "failed to start discovery: {source}"),
            Self::Shutdown(source) => {
                write!(formatter, "failed to stop discovery cleanly: {source}")
            }
            Self::Output(source) => write!(formatter, "failed to write command output: {source}"),
        }
    }
}

impl Error for DiscoveryCliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Interrupt(source) | Self::Output(source) => Some(source),
            Self::Start(source) | Self::Shutdown(source) => Some(source),
        }
    }
}

/// Cooperative cancellation for a discovery observation pass.
pub(crate) trait Cancellation {
    /// Reports whether the user has asked the pass to stop early.
    fn is_cancelled(&self) -> bool;
}

/// Process-wide flag raised by the OS interrupt handler.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// A [`Cancellation`] backed by a Ctrl+C / console interrupt handler.
#[derive(Clone, Copy)]
pub(crate) struct SignalCancellation;

impl SignalCancellation {
    /// Installs the process interrupt handler.
    pub(crate) fn install() -> Result<Self, io::Error> {
        install_interrupt_handler()?;
        Ok(Self)
    }
}

impl Cancellation for SignalCancellation {
    fn is_cancelled(&self) -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }
}

#[cfg(unix)]
fn install_interrupt_handler() -> Result<(), io::Error> {
    extern "C" fn on_interrupt(_signal: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }

    let handler = on_interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: `on_interrupt` only performs an atomic store, which is
    // async-signal-safe, and the previous disposition is never restored.
    let previous = unsafe { libc::signal(libc::SIGINT, handler) };
    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn install_interrupt_handler() -> Result<(), io::Error> {
    use windows_sys::Win32::System::Console::{CTRL_C_EVENT, SetConsoleCtrlHandler};
    use windows_sys::core::BOOL;

    unsafe extern "system" fn on_interrupt(event: u32) -> BOOL {
        if event == CTRL_C_EVENT {
            INTERRUPTED.store(true, Ordering::SeqCst);
            1
        } else {
            0
        }
    }

    // SAFETY: the console control callback only performs an atomic store.
    if unsafe { SetConsoleCtrlHandler(Some(on_interrupt), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn install_interrupt_handler() -> Result<(), io::Error> {
    // No portable interrupt primitive here; the bounded window still bounds the run.
    Ok(())
}

/// One observation pass over core discovery state.
///
/// `next_transition` returns `None` when the pass is over: the window elapsed,
/// the backend closed, or the run was interrupted. Implementations own their
/// backend and lifecycle state and release the backend in `stop`.
pub(crate) trait DiscoverySession {
    /// Applies the next observed browser event and returns its transition.
    fn next_transition(&mut self, now: Duration) -> Option<DiscoveredPeerTransition>;
    /// Asks core to expire entries older than `stale_after` at `now`.
    fn expire(&mut self, now: Duration, stale_after: Duration) -> Vec<DiscoveredPeerTransition>;
    /// Stops the underlying discovery resources; harmless to call after success.
    fn stop(&mut self) -> Result<(), DiscoveryBrowserError>;
    /// Renders the currently visible peers.
    fn snapshot(&self) -> Vec<DeviceCard>;
}

/// The production session: a real DNS-SD browser feeding core lifecycle state.
pub(crate) struct BrowserSession {
    browser: DiscoveryBrowser,
    state: DiscoveredPeerState,
    deadline: Instant,
    cancel: SignalCancellation,
}

impl BrowserSession {
    /// Starts a browser session that observes events for at most `window`.
    pub(crate) fn start(
        window: Duration,
        cancel: SignalCancellation,
    ) -> Result<Self, DiscoveryBrowserError> {
        Ok(Self {
            browser: DiscoveryBrowser::start()?,
            state: DiscoveredPeerState::new(),
            deadline: Instant::now() + window,
            cancel,
        })
    }
}

impl DiscoverySession for BrowserSession {
    fn next_transition(&mut self, now: Duration) -> Option<DiscoveredPeerTransition> {
        loop {
            if let Some(event) = self.browser.poll_event() {
                return Some(self.state.apply(event, now));
            }
            if self.cancel.is_cancelled() || Instant::now() >= self.deadline {
                return None;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn expire(&mut self, now: Duration, stale_after: Duration) -> Vec<DiscoveredPeerTransition> {
        self.state.expire(now, stale_after)
    }

    fn stop(&mut self) -> Result<(), DiscoveryBrowserError> {
        self.browser.stop()
    }

    fn snapshot(&self) -> Vec<DeviceCard> {
        self.state.iter().map(DeviceCard::from_peer).collect()
    }
}

/// Runs one observation pass and writes the report to `out`.
///
/// Transitions are collected at caller-supplied times; when `--stale-after` is
/// set, core expiry is invoked after each event and once at the end. The session
/// is always stopped before returning, and a cleanup failure is surfaced as a
/// typed error only after the collected results have been written.
pub(crate) fn observe<S, C, X, W>(
    args: &DiscoverArgs,
    session: &mut S,
    clock: &mut C,
    cancel: &X,
    out: &mut W,
) -> Result<(), DiscoveryCliError>
where
    S: DiscoverySession,
    C: FnMut() -> Duration,
    X: Cancellation,
    W: Write,
{
    let stale_after = args.stale_after.map(Duration::from_secs);
    let mut events = Vec::new();

    while !cancel.is_cancelled() {
        let Some(transition) = session.next_transition(clock()) else {
            break;
        };
        record(args.events, &mut events, &transition);
        if let Some(window) = stale_after {
            for expired in session.expire(clock(), window) {
                record(args.events, &mut events, &expired);
            }
        }
    }
    if let Some(window) = stale_after {
        for expired in session.expire(clock(), window) {
            record(args.events, &mut events, &expired);
        }
    }

    let stop_result = session.stop();

    let cards = session.snapshot();
    write_report(args.events, &events, &cards, out)?;

    stop_result.map_err(DiscoveryCliError::Shutdown)
}

fn record(show_events: bool, events: &mut Vec<String>, transition: &DiscoveredPeerTransition) {
    if show_events {
        events.push(render_transition(transition));
    }
}

/// A render-ready projection of one visible peer, decoupled from core types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceCard {
    session: String,
    name: Option<String>,
    platform: Option<DiscoveryPlatformHint>,
    protocol_major: u16,
    addresses: Vec<String>,
}

impl DeviceCard {
    fn from_peer(peer: &DiscoveredPeer) -> Self {
        let port = peer.port();
        Self {
            session: peer.key().as_str().to_owned(),
            name: peer.metadata().name().map(|hint| hint.as_str().to_owned()),
            platform: peer.metadata().platform(),
            protocol_major: peer.protocol_major(),
            addresses: peer
                .endpoints()
                .iter()
                .map(|endpoint| socket_address(endpoint.address(), endpoint.scope_id(), port))
                .collect(),
        }
    }
}

fn socket_address(address: IpAddr, scope_id: Option<u32>, port: u16) -> String {
    match address {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => match scope_id {
            Some(scope) => format!("[{v6}%{scope}]:{port}"),
            None => format!("[{v6}]:{port}"),
        },
    }
}

fn render_transition(transition: &DiscoveredPeerTransition) -> String {
    match transition {
        DiscoveredPeerTransition::Appeared(key) => format!("appeared   {}", key.as_str()),
        DiscoveredPeerTransition::Refreshed(key) => format!("refreshed  {}", key.as_str()),
        DiscoveredPeerTransition::Updated(key) => format!("updated    {}", key.as_str()),
        DiscoveredPeerTransition::Removed { key, reason } => match reason {
            DiscoveredPeerRemovalReason::Explicit => {
                format!("removed    {}  (no longer advertised)", key.as_str())
            }
            DiscoveredPeerRemovalReason::Expired => {
                format!("expired    {}  (not re-observed)", key.as_str())
            }
        },
        DiscoveredPeerTransition::Noop { key, reason } => match reason {
            DiscoveredPeerNoopReason::AlreadyAbsent => {
                format!("ignored    {}  (already absent)", key.as_str())
            }
            DiscoveredPeerNoopReason::Stale => {
                format!("ignored    {}  (superseded observation)", key.as_str())
            }
        },
        DiscoveredPeerTransition::Rejected(error) => format!("rejected   {error}"),
    }
}

fn write_report<W: Write>(
    show_events: bool,
    events: &[String],
    cards: &[DeviceCard],
    out: &mut W,
) -> Result<(), DiscoveryCliError> {
    put(out, ADVISORY_NOTICE)?;

    if show_events {
        put(out, "")?;
        if events.is_empty() {
            put(out, "No discovery events were observed.")?;
        } else {
            for line in events {
                put(out, line)?;
            }
        }
    }

    put(out, "")?;
    render_snapshot(cards, out)
}

fn render_snapshot<W: Write>(cards: &[DeviceCard], out: &mut W) -> Result<(), DiscoveryCliError> {
    if cards.is_empty() {
        return put(out, "No nearby devices are currently visible.");
    }

    let mut ordered: Vec<&DeviceCard> = cards.iter().collect();
    ordered.sort_by(|left, right| left.session.cmp(&right.session));

    put(
        out,
        &format!("{} nearby device(s) currently visible:", ordered.len()),
    )?;
    for card in ordered {
        put(out, "")?;
        put(
            out,
            &format!(
                "- {} ({})",
                card.name.as_deref().unwrap_or("unnamed"),
                platform_label(card.platform),
            ),
        )?;
        put(out, &format!("  session:  {}", card.session))?;
        put(out, &format!("  protocol: {}", card.protocol_major))?;
        put(out, &format!("  address:  {}", card.addresses.join(", ")))?;
    }
    Ok(())
}

const fn platform_label(platform: Option<DiscoveryPlatformHint>) -> &'static str {
    match platform {
        Some(DiscoveryPlatformHint::MacOs) => "macOS",
        Some(DiscoveryPlatformHint::Windows) => "Windows",
        Some(DiscoveryPlatformHint::Linux) => "Linux",
        None => "unknown platform",
    }
}

fn put<W: Write>(out: &mut W, text: &str) -> Result<(), DiscoveryCliError> {
    writeln!(out, "{text}").map_err(DiscoveryCliError::Output)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use local_transfer_core::browser::{DiscoveryBrowserError, TransientDiscoveryKey};
    use local_transfer_core::discovered_peers::{
        DiscoveredPeerNoopReason, DiscoveredPeerRemovalReason, DiscoveredPeerTransition,
    };
    use local_transfer_core::discovery::DiscoveryPlatformHint;

    use super::{
        Cancellation, DeviceCard, DiscoverArgs, DiscoveryCliError, DiscoverySession, observe,
        render_transition, write_report,
    };

    fn key(instance: &str) -> TransientDiscoveryKey {
        TransientDiscoveryKey::new(format!("{instance}._local-transfer._tcp.local.")).unwrap()
    }

    /// The public API exposes no error constructor; a rejected key yields a real typed error.
    fn browser_error() -> DiscoveryBrowserError {
        TransientDiscoveryKey::new("not a service name").unwrap_err()
    }

    fn appeared(instance: &str) -> DiscoveredPeerTransition {
        DiscoveredPeerTransition::Appeared(key(instance))
    }

    fn expired(instance: &str) -> DiscoveredPeerTransition {
        DiscoveredPeerTransition::Removed {
            key: key(instance),
            reason: DiscoveredPeerRemovalReason::Expired,
        }
    }

    struct FakeSession {
        transitions: VecDeque<DiscoveredPeerTransition>,
        expirations: VecDeque<Vec<DiscoveredPeerTransition>>,
        cards: Vec<DeviceCard>,
        next_calls: usize,
        expire_calls: usize,
        stop_calls: usize,
        stop_fails: bool,
    }

    impl FakeSession {
        fn empty() -> Self {
            Self {
                transitions: VecDeque::new(),
                expirations: VecDeque::new(),
                cards: Vec::new(),
                next_calls: 0,
                expire_calls: 0,
                stop_calls: 0,
                stop_fails: false,
            }
        }

        fn with_transitions(transitions: Vec<DiscoveredPeerTransition>) -> Self {
            let mut session = Self::empty();
            session.transitions = transitions.into();
            session
        }

        fn failing_stop(mut self) -> Self {
            self.stop_fails = true;
            self
        }
    }

    impl DiscoverySession for FakeSession {
        fn next_transition(&mut self, _now: Duration) -> Option<DiscoveredPeerTransition> {
            self.next_calls += 1;
            self.transitions.pop_front()
        }

        fn expire(
            &mut self,
            _now: Duration,
            _stale_after: Duration,
        ) -> Vec<DiscoveredPeerTransition> {
            self.expire_calls += 1;
            self.expirations.pop_front().unwrap_or_default()
        }

        fn stop(&mut self) -> Result<(), DiscoveryBrowserError> {
            self.stop_calls += 1;
            if self.stop_fails {
                Err(browser_error())
            } else {
                Ok(())
            }
        }

        fn snapshot(&self) -> Vec<DeviceCard> {
            self.cards.clone()
        }
    }

    struct FakeCancellation {
        checks_before_cancel: Cell<u32>,
    }

    impl FakeCancellation {
        fn never() -> Self {
            Self {
                checks_before_cancel: Cell::new(u32::MAX),
            }
        }

        fn after(checks: u32) -> Self {
            Self {
                checks_before_cancel: Cell::new(checks),
            }
        }
    }

    impl Cancellation for FakeCancellation {
        fn is_cancelled(&self) -> bool {
            let left = self.checks_before_cancel.get();
            if left == 0 {
                return true;
            }
            self.checks_before_cancel.set(left - 1);
            false
        }
    }

    fn args(events: bool) -> DiscoverArgs {
        DiscoverArgs {
            events,
            window: 3,
            stale_after: None,
        }
    }

    fn monotonic_clock() -> impl FnMut() -> Duration {
        let mut ticks = 0_u64;
        move || {
            ticks += 1;
            Duration::from_secs(ticks)
        }
    }

    fn run_session<X: Cancellation>(
        args: &DiscoverArgs,
        session: &mut FakeSession,
        cancel: &X,
    ) -> (String, Result<(), DiscoveryCliError>) {
        let mut clock = monotonic_clock();
        let mut out = Vec::new();
        let result = observe(args, session, &mut clock, cancel, &mut out);
        (String::from_utf8(out).unwrap(), result)
    }

    fn run(
        args: &DiscoverArgs,
        session: &mut FakeSession,
    ) -> (String, Result<(), DiscoveryCliError>) {
        run_session(args, session, &FakeCancellation::never())
    }

    fn card(
        session: &str,
        name: Option<&str>,
        platform: Option<DiscoveryPlatformHint>,
        addresses: &[&str],
    ) -> DeviceCard {
        DeviceCard {
            session: session.to_owned(),
            name: name.map(str::to_owned),
            platform,
            protocol_major: 1,
            addresses: addresses.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn snapshot(cards: &[DeviceCard]) -> String {
        let mut out = Vec::new();
        write_report(false, &[], cards, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn snapshot_declares_discovery_advisory_and_unauthenticated() {
        let output = snapshot(&[card(
            "lt-a._local-transfer._tcp.local.",
            Some("Studio"),
            Some(DiscoveryPlatformHint::Linux),
            &["192.0.2.10:4242"],
        )]);

        assert!(output.contains("advisory and unauthenticated"));
        assert!(output.contains("not paired, trusted, or authenticated"));
        assert!(!output.contains("trusted device"));
        assert!(!output.contains("is verified"));
        assert!(!output.to_lowercase().contains("paired with"));
    }

    #[test]
    fn snapshot_without_devices_is_explicit() {
        let output = snapshot(&[]);

        assert!(output.contains("No nearby devices are currently visible."));
        assert!(output.contains("advisory and unauthenticated"));
    }

    #[test]
    fn snapshot_renders_session_platform_protocol_and_address() {
        let output = snapshot(&[card(
            "lt-desk._local-transfer._tcp.local.",
            Some("Studio"),
            Some(DiscoveryPlatformHint::MacOs),
            &["192.0.2.5:4242", "[fe80::1%3]:4242"],
        )]);

        assert!(output.contains("- Studio (macOS)"));
        assert!(output.contains("session:  lt-desk._local-transfer._tcp.local."));
        assert!(output.contains("protocol: 1"));
        assert!(output.contains("address:  192.0.2.5:4242, [fe80::1%3]:4242"));
    }

    #[test]
    fn snapshot_keeps_same_name_devices_distinguishable() {
        let output = snapshot(&[
            card(
                "lt-one._local-transfer._tcp.local.",
                Some("Studio"),
                Some(DiscoveryPlatformHint::Linux),
                &["192.0.2.10:4242"],
            ),
            card(
                "lt-two._local-transfer._tcp.local.",
                Some("Studio"),
                Some(DiscoveryPlatformHint::Linux),
                &["192.0.2.20:4242"],
            ),
        ]);

        assert_eq!(output.matches("- Studio (Linux)").count(), 2);
        assert!(output.contains("session:  lt-one._local-transfer._tcp.local."));
        assert!(output.contains("session:  lt-two._local-transfer._tcp.local."));
        assert!(output.contains("2 nearby device(s) currently visible:"));
    }

    #[test]
    fn snapshot_orders_devices_by_session_key() {
        let output = snapshot(&[
            card(
                "lt-zeta._local-transfer._tcp.local.",
                Some("Z"),
                Some(DiscoveryPlatformHint::Linux),
                &["192.0.2.9:4242"],
            ),
            card(
                "lt-alpha._local-transfer._tcp.local.",
                Some("A"),
                Some(DiscoveryPlatformHint::Linux),
                &["192.0.2.1:4242"],
            ),
        ]);

        let alpha = output.find("lt-alpha").unwrap();
        let zeta = output.find("lt-zeta").unwrap();
        assert!(alpha < zeta);
    }

    #[test]
    fn snapshot_names_unset_name_and_platform_conservatively() {
        let output = snapshot(&[card(
            "lt-x._local-transfer._tcp.local.",
            None,
            None,
            &["192.0.2.10:4242"],
        )]);

        assert!(output.contains("- unnamed (unknown platform)"));
    }

    #[test]
    fn transition_lines_are_distinct_per_lifecycle_kind() {
        let anchor = key("lt-evt");

        assert!(
            render_transition(&DiscoveredPeerTransition::Appeared(anchor.clone()))
                .starts_with("appeared")
        );
        assert!(
            render_transition(&DiscoveredPeerTransition::Updated(anchor.clone()))
                .starts_with("updated")
        );

        let removed = render_transition(&DiscoveredPeerTransition::Removed {
            key: anchor.clone(),
            reason: DiscoveredPeerRemovalReason::Explicit,
        });
        assert!(removed.starts_with("removed"));
        assert!(removed.contains("no longer advertised"));

        let stale = render_transition(&expired("lt-evt"));
        assert!(stale.starts_with("expired"));

        let ignored = render_transition(&DiscoveredPeerTransition::Noop {
            key: anchor.clone(),
            reason: DiscoveredPeerNoopReason::AlreadyAbsent,
        });
        assert!(ignored.starts_with("ignored"));
        assert!(ignored.contains("already absent"));

        let superseded = render_transition(&DiscoveredPeerTransition::Noop {
            key: anchor,
            reason: DiscoveredPeerNoopReason::Stale,
        });
        assert!(superseded.starts_with("ignored"));
    }

    #[test]
    fn refresh_is_never_reported_as_a_new_appearance() {
        let line = render_transition(&DiscoveredPeerTransition::Refreshed(key("lt-r")));

        assert!(line.contains("refreshed"));
        assert!(!line.contains("appeared"));
    }

    #[test]
    fn rejected_transition_shows_a_safe_message_only() {
        let error = TransientDiscoveryKey::new("\u{7}control-name").unwrap_err();

        let line = render_transition(&DiscoveredPeerTransition::Rejected(error));

        assert!(line.starts_with("rejected"));
        assert!(line.contains("invalid transient DNS-SD service key"));
        assert!(!line.contains("control-name"));
        assert!(!line.contains('\u{7}'));
    }

    #[test]
    fn observe_reports_empty_snapshot_and_always_stops_the_session() {
        let mut session = FakeSession::empty();

        let (output, result) = run(&args(false), &mut session);

        assert!(result.is_ok());
        assert_eq!(session.stop_calls, 1);
        assert!(output.contains("advisory and unauthenticated"));
        assert!(output.contains("No nearby devices are currently visible."));
    }

    #[test]
    fn observe_streams_events_in_order_before_the_snapshot() {
        let mut session = FakeSession::with_transitions(vec![
            DiscoveredPeerTransition::Noop {
                key: key("lt-ghost"),
                reason: DiscoveredPeerNoopReason::AlreadyAbsent,
            },
            DiscoveredPeerTransition::Rejected(browser_error()),
        ]);

        let (output, result) = run(&args(true), &mut session);

        assert!(result.is_ok());
        assert_eq!(session.stop_calls, 1);
        let ignored = output.find("ignored").unwrap();
        let rejected = output.find("rejected").unwrap();
        let listing = output.find("No nearby devices").unwrap();
        assert!(ignored < rejected && rejected < listing);
        assert!(output.contains("already absent"));
    }

    #[test]
    fn observe_hides_event_lines_without_the_events_flag() {
        let mut session = FakeSession::with_transitions(vec![
            DiscoveredPeerTransition::Noop {
                key: key("lt-ghost"),
                reason: DiscoveredPeerNoopReason::AlreadyAbsent,
            },
            DiscoveredPeerTransition::Rejected(browser_error()),
        ]);

        let (output, _) = run(&args(false), &mut session);

        assert!(!output.contains("ignored"));
        assert!(!output.contains("rejected"));
        assert!(output.contains("No nearby devices are currently visible."));
    }

    #[test]
    fn observe_reports_cleanup_failure_as_a_typed_error_after_writing_results() {
        let mut session = FakeSession::empty().failing_stop();

        let (output, result) = run(&args(false), &mut session);

        assert_eq!(session.stop_calls, 1);
        assert!(matches!(result, Err(DiscoveryCliError::Shutdown(_))));
        assert!(output.contains("advisory and unauthenticated"));
    }

    #[test]
    fn observe_never_treats_a_rejected_event_as_a_visible_device() {
        let mut session =
            FakeSession::with_transitions(vec![
                DiscoveredPeerTransition::Rejected(browser_error()),
            ]);

        let (output, _) = run(&args(true), &mut session);

        assert!(output.contains("rejected"));
        assert!(output.contains("No nearby devices are currently visible."));
    }

    #[test]
    fn observe_renders_the_session_snapshot() {
        let mut session = FakeSession::empty();
        session.cards = vec![card(
            "lt-desk._local-transfer._tcp.local.",
            Some("Desk"),
            Some(DiscoveryPlatformHint::Linux),
            &["192.0.2.7:4242"],
        )];

        let (output, _) = run(&args(false), &mut session);

        assert!(output.contains("- Desk (Linux)"));
        assert!(output.contains("session:  lt-desk._local-transfer._tcp.local."));
    }

    #[test]
    fn observe_stops_consuming_transitions_once_cancelled() {
        let mut session = FakeSession::with_transitions(vec![
            appeared("lt-a"),
            appeared("lt-b"),
            appeared("lt-c"),
        ]);

        let cancel = FakeCancellation::after(1);
        let (output, result) = run_session(&args(true), &mut session, &cancel);

        assert!(result.is_ok());
        assert_eq!(session.next_calls, 1);
        assert_eq!(session.stop_calls, 1);
        assert!(output.contains("appeared   lt-a._local-transfer._tcp.local."));
        assert!(!output.contains("lt-b"));
        assert!(!output.contains("lt-c"));
    }

    #[test]
    fn observe_reports_cleanup_failure_after_cancellation() {
        let mut session = FakeSession::with_transitions(vec![appeared("lt-a")]).failing_stop();

        let cancel = FakeCancellation::after(1);
        let (output, result) = run_session(&args(false), &mut session, &cancel);

        assert_eq!(session.stop_calls, 1);
        assert!(matches!(result, Err(DiscoveryCliError::Shutdown(_))));
        assert!(output.contains("advisory and unauthenticated"));
    }

    #[test]
    fn observe_cancelled_before_any_transition_still_stops_and_reports() {
        let mut session = FakeSession::with_transitions(vec![appeared("lt-a")]);

        let cancel = FakeCancellation::after(0);
        let (output, result) = run_session(&args(false), &mut session, &cancel);

        assert!(result.is_ok());
        assert_eq!(session.next_calls, 0);
        assert_eq!(session.stop_calls, 1);
        assert!(output.contains("No nearby devices are currently visible."));
    }

    #[test]
    fn stale_after_renders_core_expiry_transitions() {
        let mut session = FakeSession::with_transitions(vec![appeared("lt-desk")]);
        session.expirations.push_back(Vec::new()); // after the appearance
        session.expirations.push_back(vec![expired("lt-desk")]); // final sweep

        let args = DiscoverArgs {
            events: true,
            window: 5,
            stale_after: Some(2),
        };
        let (output, result) = run(&args, &mut session);

        assert!(result.is_ok());
        assert!(output.contains("appeared   lt-desk._local-transfer._tcp.local."));
        assert!(
            output.contains("expired    lt-desk._local-transfer._tcp.local.  (not re-observed)")
        );
        assert_eq!(session.expire_calls, 2);
    }

    #[test]
    fn without_stale_after_core_expiry_is_never_invoked() {
        let mut session = FakeSession::with_transitions(vec![appeared("lt-a")]);
        session.expirations.push_back(vec![expired("lt-a")]);

        let (output, _) = run(&args(true), &mut session);

        assert_eq!(session.expire_calls, 0);
        assert!(!output.contains("expired"));
        assert_eq!(session.expirations.len(), 1);
    }
}
