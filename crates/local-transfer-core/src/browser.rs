//! Bounded DNS-SD browsing translated into unauthenticated domain events.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::time::Duration;

use mdns_sd::{DaemonEvent, DaemonStatus, ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent};

use crate::discovery::{
    DISCOVERY_SERVICE_TYPE, DiscoveryMetadata, DiscoveryMetadataError, DiscoveryProtocolRange,
    DiscoveryTxtEntry,
};

/// Maximum number of unique resolved addresses accepted for one advertisement.
pub const MAX_DISCOVERED_ENDPOINTS: usize = 16;
/// Maximum encoded size of a transient DNS-SD service fullname.
pub const MAX_TRANSIENT_DISCOVERY_KEY_BYTES: usize = 255;

const LOCAL_SERVICE_TYPE: &str = "_local-transfer._tcp.local.";
const TRANSIENT_KEY_SUFFIX: &str = "._local-transfer._tcp.local.";
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// An untrusted, session-scoped DNS-SD service fullname.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransientDiscoveryKey(String);

impl TransientDiscoveryKey {
    /// Validates a remote DNS-SD fullname for bounded in-memory correlation.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DiscoveryBrowserError> {
        let value = value.as_ref();
        let instance_len = value.len().checked_sub(TRANSIENT_KEY_SUFFIX.len());
        let has_service_suffix = instance_len.is_some_and(|offset| {
            value
                .get(offset..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(TRANSIENT_KEY_SUFFIX))
        });
        let Some(instance_len) = instance_len else {
            return Err(DiscoveryBrowserError::without_source(
                DiscoveryBrowserErrorKind::InvalidTransientKey,
            ));
        };
        if value.len() > MAX_TRANSIENT_DISCOVERY_KEY_BYTES
            || !has_service_suffix
            || instance_len == 0
            || value.chars().any(char::is_control)
        {
            return Err(DiscoveryBrowserError::without_source(
                DiscoveryBrowserErrorKind::InvalidTransientKey,
            ));
        }
        Ok(Self(format!(
            "{}{TRANSIENT_KEY_SUFFIX}",
            &value[..instance_len]
        )))
    }

    /// Returns the transient DNS-SD fullname.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One resolved IP endpoint, retaining the IPv6 interface scope when present.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryEndpoint {
    address: IpAddr,
    scope_id: Option<u32>,
}

impl DiscoveryEndpoint {
    /// Creates an IPv4 endpoint.
    #[must_use]
    pub(crate) const fn ipv4(address: Ipv4Addr) -> Self {
        Self {
            address: IpAddr::V4(address),
            scope_id: None,
        }
    }

    /// Creates an IPv6 endpoint with its DNS-SD interface scope identifier.
    #[must_use]
    pub(crate) const fn ipv6(address: Ipv6Addr, scope_id: u32) -> Self {
        Self {
            address: IpAddr::V6(address),
            scope_id: Some(scope_id),
        }
    }

    /// Returns the resolved IP address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Returns the interface scope for IPv6 or `None` for IPv4.
    #[must_use]
    pub const fn scope_id(self) -> Option<u32> {
        self.scope_id
    }
}

/// A bounded, compatible, unauthenticated resolved service snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredPeer {
    key: TransientDiscoveryKey,
    metadata: DiscoveryMetadata,
    port: NonZeroU16,
    endpoints: Vec<DiscoveryEndpoint>,
    protocol_major: u16,
}

impl DiscoveredPeer {
    /// Returns the transient advertisement key, not a permanent peer identity.
    #[must_use]
    pub const fn key(&self) -> &TransientDiscoveryKey {
        &self.key
    }

    /// Returns the validated, advisory discovery metadata.
    #[must_use]
    pub const fn metadata(&self) -> &DiscoveryMetadata {
        &self.metadata
    }

    /// Returns the resolved non-zero TCP service port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port.get()
    }

    /// Returns the bounded, sorted, deduplicated resolved endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[DiscoveryEndpoint] {
        &self.endpoints
    }

    /// Returns the highest application-protocol major shared with this release.
    #[must_use]
    pub const fn protocol_major(&self) -> u16 {
        self.protocol_major
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        key: TransientDiscoveryKey,
        metadata: DiscoveryMetadata,
        port: NonZeroU16,
        endpoints: Vec<DiscoveryEndpoint>,
        protocol_major: u16,
    ) -> Self {
        Self {
            key,
            metadata,
            port,
            endpoints,
            protocol_major,
        }
    }
}

/// The category of a browsing or remote-resolution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryBrowserErrorKind {
    /// The private mDNS daemon could not be created.
    Initialization,
    /// The daemon rejected the canonical browse request.
    Browse,
    /// A service fullname was empty, oversized, or contained control characters.
    InvalidTransientKey,
    /// A resolution omitted required endpoint information.
    MalformedResolution,
    /// A resolved service advertised port zero.
    InvalidPort,
    /// Unique resolved endpoints exceeded the explicit bound.
    EndpointLimit,
    /// TXT metadata failed the shared discovery-schema validation.
    Metadata,
    /// The peer has no application-protocol major in common with this release.
    IncompatibleProtocol,
    /// The mDNS daemon reported an asynchronous failure.
    Daemon,
    /// The daemon rejected the stop-browse request.
    StopBrowse,
    /// Daemon shutdown failed or was not acknowledged before the timeout.
    Shutdown,
}

/// A typed browser failure that keeps infrastructure types behind the boundary.
#[derive(Debug)]
pub struct DiscoveryBrowserError {
    kind: DiscoveryBrowserErrorKind,
    key: Option<TransientDiscoveryKey>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl DiscoveryBrowserError {
    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> DiscoveryBrowserErrorKind {
        self.kind
    }

    /// Returns the affected transient advertisement key when safely available.
    #[must_use]
    pub const fn key(&self) -> Option<&TransientDiscoveryKey> {
        self.key.as_ref()
    }

    fn without_source(kind: DiscoveryBrowserErrorKind) -> Self {
        Self {
            kind,
            key: None,
            source: None,
        }
    }

    fn for_key(kind: DiscoveryBrowserErrorKind, key: TransientDiscoveryKey) -> Self {
        Self {
            kind,
            key: Some(key),
            source: None,
        }
    }

    fn with_source(
        kind: DiscoveryBrowserErrorKind,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            key: None,
            source: Some(Box::new(source)),
        }
    }

    fn for_key_with_source(
        kind: DiscoveryBrowserErrorKind,
        key: TransientDiscoveryKey,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            key: Some(key),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for DiscoveryBrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            DiscoveryBrowserErrorKind::Initialization => "failed to initialize mDNS browsing",
            DiscoveryBrowserErrorKind::Browse => "failed to start the DNS-SD browse request",
            DiscoveryBrowserErrorKind::InvalidTransientKey => {
                "invalid transient DNS-SD service key"
            }
            DiscoveryBrowserErrorKind::MalformedResolution => {
                "resolved DNS-SD service has no usable endpoints"
            }
            DiscoveryBrowserErrorKind::InvalidPort => {
                "resolved DNS-SD service advertised port zero"
            }
            DiscoveryBrowserErrorKind::EndpointLimit => {
                "resolved DNS-SD service exceeds the endpoint limit"
            }
            DiscoveryBrowserErrorKind::Metadata => "invalid discovery TXT metadata",
            DiscoveryBrowserErrorKind::IncompatibleProtocol => {
                "discovered service has no compatible protocol major"
            }
            DiscoveryBrowserErrorKind::Daemon => "the mDNS browser daemon reported an error",
            DiscoveryBrowserErrorKind::StopBrowse => "failed to stop the DNS-SD browse request",
            DiscoveryBrowserErrorKind::Shutdown => "failed to shut down the mDNS browser daemon",
        };
        formatter.write_str(message)
    }
}

impl Error for DiscoveryBrowserError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// A transient, unauthenticated discovery-session event.
#[derive(Debug)]
pub enum DiscoveryBrowserEvent {
    /// First valid compatible resolution for an advertisement key.
    Added(DiscoveredPeer),
    /// Meaningful validated state changed for an already resolved advertisement.
    Updated(DiscoveredPeer),
    /// An equivalent valid resolution refreshed advertisement liveness.
    Refreshed(DiscoveredPeer),
    /// A previously resolved advertisement is no longer visible.
    Removed(TransientDiscoveryKey),
    /// A daemon, lifecycle, or hostile-input failure occurred.
    Error(DiscoveryBrowserError),
}

/// An owned synchronous browser for compatible local-transfer advertisements.
///
/// Starting means the daemon accepted a browse command; it does not mean any
/// service has been discovered. [`poll_event`](Self::poll_event) never blocks.
pub struct DiscoveryBrowser {
    session: BrowserSession<MdnsBrowserBackend>,
}

impl DiscoveryBrowser {
    /// Starts browsing the canonical local-transfer service type.
    pub fn start() -> Result<Self, DiscoveryBrowserError> {
        let session = BrowserSession::start(MdnsBrowserBackend::start)?;
        Ok(Self { session })
    }

    /// Processes at most one backend event and returns a translated event without blocking.
    pub fn poll_event(&mut self) -> Option<DiscoveryBrowserEvent> {
        self.session.poll_event()
    }

    /// Stops browsing and waits at most two seconds for daemon shutdown.
    ///
    /// Repeated calls after a successful stop are harmless.
    pub fn stop(&mut self) -> Result<(), DiscoveryBrowserError> {
        self.session.stop()
    }
}

impl fmt::Debug for DiscoveryBrowser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryBrowser")
            .field("active", &self.session.active)
            .finish_non_exhaustive()
    }
}

struct RawResolvedService {
    fullname: String,
    port: u16,
    endpoints: Vec<DiscoveryEndpoint>,
    txt: Vec<DiscoveryTxtEntry>,
}

enum RawBrowserEvent {
    Resolved(RawResolvedService),
    Removed(String),
    Error(DiscoveryBrowserError),
}

/// Coalesces raw resolutions into deduplicated peers keyed by transient name.
#[derive(Default)]
struct BrowserState {
    peers: HashMap<TransientDiscoveryKey, DiscoveredPeer>,
}

impl BrowserState {
    fn translate(&mut self, event: RawBrowserEvent) -> Option<DiscoveryBrowserEvent> {
        match event {
            RawBrowserEvent::Resolved(resolved) => Some(match self.resolve(resolved) {
                Ok(Some(event)) => event,
                Ok(None) => return None,
                Err(error) => DiscoveryBrowserEvent::Error(error),
            }),
            RawBrowserEvent::Removed(fullname) => {
                let key = match TransientDiscoveryKey::new(fullname) {
                    Ok(key) => key,
                    Err(error) => return Some(DiscoveryBrowserEvent::Error(error)),
                };
                self.peers
                    .remove(&key)
                    .map(|_| DiscoveryBrowserEvent::Removed(key))
            }
            RawBrowserEvent::Error(error) => Some(DiscoveryBrowserEvent::Error(error)),
        }
    }

    fn resolve(
        &mut self,
        resolved: RawResolvedService,
    ) -> Result<Option<DiscoveryBrowserEvent>, DiscoveryBrowserError> {
        let key = TransientDiscoveryKey::new(resolved.fullname)?;
        let port = NonZeroU16::new(resolved.port).ok_or_else(|| {
            DiscoveryBrowserError::for_key(DiscoveryBrowserErrorKind::InvalidPort, key.clone())
        })?;

        let endpoints: BTreeSet<_> = resolved.endpoints.into_iter().collect();
        if endpoints.is_empty() {
            return Err(DiscoveryBrowserError::for_key(
                DiscoveryBrowserErrorKind::MalformedResolution,
                key,
            ));
        }
        if endpoints.len() > MAX_DISCOVERED_ENDPOINTS {
            return Err(DiscoveryBrowserError::for_key(
                DiscoveryBrowserErrorKind::EndpointLimit,
                key,
            ));
        }

        let metadata = DiscoveryMetadata::from_txt_entries(&resolved.txt).map_err(|source| {
            DiscoveryBrowserError::for_key_with_source(
                DiscoveryBrowserErrorKind::Metadata,
                key.clone(),
                source,
            )
        })?;
        let protocol_major = DiscoveryProtocolRange::initial()
            .highest_compatible_version(metadata.protocols())
            .ok_or_else(|| {
                DiscoveryBrowserError::for_key(
                    DiscoveryBrowserErrorKind::IncompatibleProtocol,
                    key.clone(),
                )
            })?;
        let peer = DiscoveredPeer {
            key: key.clone(),
            metadata,
            port,
            endpoints: endpoints.into_iter().collect(),
            protocol_major,
        };

        match self.peers.get(&key) {
            Some(previous) if previous == &peer => Ok(Some(DiscoveryBrowserEvent::Refreshed(peer))),
            Some(_) => {
                self.peers.insert(key, peer.clone());
                Ok(Some(DiscoveryBrowserEvent::Updated(peer)))
            }
            None => {
                self.peers.insert(key, peer.clone());
                Ok(Some(DiscoveryBrowserEvent::Added(peer)))
            }
        }
    }
}

trait BrowserBackend {
    fn poll_event(&mut self) -> Option<RawBrowserEvent>;
    fn stop(&mut self) -> Result<(), DiscoveryBrowserError>;
    fn best_effort_stop(&mut self);
}

struct BrowserSession<B: BrowserBackend> {
    backend: B,
    state: BrowserState,
    active: bool,
}

impl<B: BrowserBackend> BrowserSession<B> {
    fn start(
        start_backend: impl FnOnce() -> Result<B, DiscoveryBrowserError>,
    ) -> Result<Self, DiscoveryBrowserError> {
        Ok(Self {
            backend: start_backend()?,
            state: BrowserState::default(),
            active: true,
        })
    }

    fn poll_event(&mut self) -> Option<DiscoveryBrowserEvent> {
        if !self.active {
            return None;
        }
        self.backend
            .poll_event()
            .and_then(|raw| self.state.translate(raw))
    }

    fn stop(&mut self) -> Result<(), DiscoveryBrowserError> {
        if !self.active {
            return Ok(());
        }
        self.backend.stop()?;
        self.active = false;
        Ok(())
    }
}

impl<B: BrowserBackend> Drop for BrowserSession<B> {
    fn drop(&mut self) {
        if self.active {
            self.backend.best_effort_stop();
        }
    }
}

struct MdnsBrowserBackend {
    daemon: ServiceDaemon,
    services: mdns_sd::Receiver<ServiceEvent>,
    daemon_events: mdns_sd::Receiver<DaemonEvent>,
}

impl MdnsBrowserBackend {
    fn start() -> Result<Self, DiscoveryBrowserError> {
        debug_assert_eq!(
            LOCAL_SERVICE_TYPE,
            format!("{DISCOVERY_SERVICE_TYPE}.local.")
        );
        let daemon = ServiceDaemon::new().map_err(|source| {
            DiscoveryBrowserError::with_source(DiscoveryBrowserErrorKind::Initialization, source)
        })?;
        let daemon_events = daemon.monitor().map_err(|source| {
            let _ = daemon.shutdown();
            DiscoveryBrowserError::with_source(DiscoveryBrowserErrorKind::Initialization, source)
        })?;
        let services = daemon.browse(LOCAL_SERVICE_TYPE).map_err(|source| {
            let _ = daemon.shutdown();
            DiscoveryBrowserError::with_source(DiscoveryBrowserErrorKind::Browse, source)
        })?;
        Ok(Self {
            daemon,
            services,
            daemon_events,
        })
    }

    fn poll_daemon_error(&self) -> Option<RawBrowserEvent> {
        loop {
            match self.daemon_events.try_recv() {
                Ok(DaemonEvent::Error(source)) => {
                    return Some(RawBrowserEvent::Error(DiscoveryBrowserError::with_source(
                        DiscoveryBrowserErrorKind::Daemon,
                        source,
                    )));
                }
                Ok(_) => {}
                Err(mdns_sd::TryRecvError::Empty) => return None,
                Err(source) => {
                    return Some(RawBrowserEvent::Error(DiscoveryBrowserError::with_source(
                        DiscoveryBrowserErrorKind::Daemon,
                        source,
                    )));
                }
            }
        }
    }
}

impl BrowserBackend for MdnsBrowserBackend {
    fn poll_event(&mut self) -> Option<RawBrowserEvent> {
        if let Some(error) = self.poll_daemon_error() {
            return Some(error);
        }
        loop {
            match self.services.try_recv() {
                Ok(ServiceEvent::ServiceResolved(service)) => {
                    return Some(match raw_service(&service) {
                        Ok(resolved) => RawBrowserEvent::Resolved(resolved),
                        Err(error) => RawBrowserEvent::Error(error),
                    });
                }
                Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                    return Some(RawBrowserEvent::Removed(fullname));
                }
                Ok(_) => {}
                Err(mdns_sd::TryRecvError::Empty) => return None,
                Err(source) => {
                    return Some(RawBrowserEvent::Error(DiscoveryBrowserError::with_source(
                        DiscoveryBrowserErrorKind::Daemon,
                        source,
                    )));
                }
            }
        }
    }

    fn stop(&mut self) -> Result<(), DiscoveryBrowserError> {
        let browse_result = self
            .daemon
            .stop_browse(LOCAL_SERVICE_TYPE)
            .map_err(|source| {
                DiscoveryBrowserError::with_source(DiscoveryBrowserErrorKind::StopBrowse, source)
            });
        let shutdown_result = shutdown(&self.daemon);
        browse_result.and(shutdown_result)
    }

    fn best_effort_stop(&mut self) {
        let _ = self.daemon.stop_browse(LOCAL_SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

fn shutdown(daemon: &ServiceDaemon) -> Result<(), DiscoveryBrowserError> {
    let receiver = daemon.shutdown().map_err(|source| {
        DiscoveryBrowserError::with_source(DiscoveryBrowserErrorKind::Shutdown, source)
    })?;
    match receiver.recv_timeout(STOP_TIMEOUT) {
        Ok(DaemonStatus::Shutdown) => Ok(()),
        Ok(_) => Err(DiscoveryBrowserError::without_source(
            DiscoveryBrowserErrorKind::Shutdown,
        )),
        Err(source) => Err(DiscoveryBrowserError::with_source(
            DiscoveryBrowserErrorKind::Shutdown,
            source,
        )),
    }
}

fn raw_service(service: &ResolvedService) -> Result<RawResolvedService, DiscoveryBrowserError> {
    let key = TransientDiscoveryKey::new(service.get_fullname())?;
    let txt = service
        .get_properties()
        .iter()
        .map(|property| DiscoveryTxtEntry::new(property.key(), property.val().unwrap_or_default()))
        .collect::<Result<Vec<_>, DiscoveryMetadataError>>()
        .map_err(|source| {
            DiscoveryBrowserError::for_key_with_source(
                DiscoveryBrowserErrorKind::Metadata,
                key,
                source,
            )
        })?;
    let endpoints = service
        .get_addresses()
        .iter()
        .filter_map(|address| match address {
            ScopedIp::V4(address) => Some(DiscoveryEndpoint::ipv4(*address.addr())),
            ScopedIp::V6(address) => Some(DiscoveryEndpoint::ipv6(
                *address.addr(),
                address.scope_id().index,
            )),
            _ => None,
        })
        .collect();
    Ok(RawResolvedService {
        fullname: service.get_fullname().to_owned(),
        port: service.get_port(),
        endpoints,
        txt,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::rc::Rc;

    use super::*;
    use crate::discovered_peers::{
        DiscoveredPeerNoopReason, DiscoveredPeerRemovalReason, DiscoveredPeerState,
        DiscoveredPeerTransition,
    };
    use crate::discovery::{DiscoveryNameHint, DiscoveryPlatformHint};

    const KEY: &str = "lt-session._local-transfer._tcp.local.";

    fn txt_with_range(min: u16, max: u16) -> Vec<DiscoveryTxtEntry> {
        vec![
            DiscoveryTxtEntry::new("dv", "1").unwrap(),
            DiscoveryTxtEntry::new("pmin", min.to_string()).unwrap(),
            DiscoveryTxtEntry::new("pmax", max.to_string()).unwrap(),
        ]
    }

    fn resolved() -> RawResolvedService {
        RawResolvedService {
            fullname: KEY.to_owned(),
            port: 4242,
            endpoints: vec![DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 1))],
            txt: txt_with_range(1, 1),
        }
    }

    fn peer(event: DiscoveryBrowserEvent) -> DiscoveredPeer {
        match event {
            DiscoveryBrowserEvent::Added(peer)
            | DiscoveryBrowserEvent::Updated(peer)
            | DiscoveryBrowserEvent::Refreshed(peer) => peer,
            _ => panic!("expected resolved peer event"),
        }
    }

    fn error_kind(event: DiscoveryBrowserEvent) -> DiscoveryBrowserErrorKind {
        match event {
            DiscoveryBrowserEvent::Error(error) => error.kind(),
            _ => panic!("expected error event"),
        }
    }

    #[test]
    fn canonical_service_type_is_browsed_with_library_domain() {
        assert_eq!(DISCOVERY_SERVICE_TYPE, "_local-transfer._tcp");
        assert_eq!(LOCAL_SERVICE_TYPE, "_local-transfer._tcp.local.");
    }

    #[test]
    fn valid_resolution_adds_refreshes_and_meaningful_changes_update() {
        let mut initial_state = BrowserState::default();
        let first = initial_state
            .translate(RawBrowserEvent::Resolved(resolved()))
            .unwrap();
        let first_peer = peer(first);
        assert_eq!(first_peer.key().as_str(), KEY);
        assert_eq!(first_peer.port(), 4242);
        assert_eq!(first_peer.protocol_major(), 1);
        assert!(matches!(
            initial_state.translate(RawBrowserEvent::Resolved(resolved())),
            Some(DiscoveryBrowserEvent::Refreshed(_))
        ));

        let mut metadata_state = BrowserState::default();
        metadata_state.translate(RawBrowserEvent::Resolved(resolved()));
        let mut metadata_change = resolved();
        metadata_change
            .txt
            .push(DiscoveryTxtEntry::new("name", "Kitchen").unwrap());
        assert!(matches!(
            metadata_state.translate(RawBrowserEvent::Resolved(metadata_change)),
            Some(DiscoveryBrowserEvent::Updated(_))
        ));

        let mut port_state = BrowserState::default();
        port_state.translate(RawBrowserEvent::Resolved(resolved()));
        let mut port_change = resolved();
        port_change.port = 4343;
        assert!(matches!(
            port_state.translate(RawBrowserEvent::Resolved(port_change)),
            Some(DiscoveryBrowserEvent::Updated(_))
        ));

        let mut endpoint_state = BrowserState::default();
        endpoint_state.translate(RawBrowserEvent::Resolved(resolved()));
        let mut endpoint_change = resolved();
        endpoint_change.endpoints = vec![DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 2))];
        assert!(matches!(
            endpoint_state.translate(RawBrowserEvent::Resolved(endpoint_change)),
            Some(DiscoveryBrowserEvent::Updated(_))
        ));
    }

    #[test]
    fn reordered_and_duplicate_endpoints_coalesce_without_a_semantic_update() {
        let near = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 10));
        let far = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 20));
        let mut state = BrowserState::default();

        let mut first = resolved();
        first.endpoints = vec![near, far];
        let added = peer(state.translate(RawBrowserEvent::Resolved(first)).unwrap());
        assert_eq!(added.endpoints(), &[near, far]);

        let mut reordered = resolved();
        reordered.endpoints = vec![far, near, far, near];
        let event = state
            .translate(RawBrowserEvent::Resolved(reordered))
            .unwrap();
        assert!(matches!(event, DiscoveryBrowserEvent::Refreshed(_)));
        assert_eq!(peer(event).endpoints(), &[near, far]);
        assert_eq!(state.peers.len(), 1);
    }

    #[test]
    fn partially_overlapping_endpoint_sets_are_a_meaningful_update() {
        let a = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 10));
        let b = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 20));
        let c = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 30));
        let mut state = BrowserState::default();

        let mut first = resolved();
        first.endpoints = vec![a, b];
        state.translate(RawBrowserEvent::Resolved(first));

        let mut overlapping = resolved();
        overlapping.endpoints = vec![c, b];
        let event = state
            .translate(RawBrowserEvent::Resolved(overlapping))
            .unwrap();
        assert!(matches!(event, DiscoveryBrowserEvent::Updated(_)));
        assert_eq!(peer(event).endpoints(), &[b, c]);
        assert_eq!(state.peers.len(), 1);
    }

    #[test]
    fn multiple_interface_addresses_collapse_into_one_normalized_peer() {
        let mut state = BrowserState::default();
        let mut resolution = resolved();
        resolution.endpoints = vec![
            DiscoveryEndpoint::ipv6(Ipv6Addr::LOCALHOST, 2),
            DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 2)),
            DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 1)),
        ];

        let added = peer(
            state
                .translate(RawBrowserEvent::Resolved(resolution))
                .unwrap(),
        );

        assert_eq!(
            added.endpoints(),
            &[
                DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 2)),
                DiscoveryEndpoint::ipv6(Ipv6Addr::LOCALHOST, 2),
            ]
        );
        assert_eq!(state.peers.len(), 1);
    }

    #[test]
    fn advertisements_sharing_a_name_hint_remain_distinct_transient_keys() {
        const OTHER_KEY: &str = "lt-other._local-transfer._tcp.local.";
        let mut state = BrowserState::default();

        let mut first = resolved();
        first
            .txt
            .push(DiscoveryTxtEntry::new("name", "Studio").unwrap());
        let mut second = resolved();
        second.fullname = OTHER_KEY.to_owned();
        second.endpoints = vec![DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 99))];
        second
            .txt
            .push(DiscoveryTxtEntry::new("name", "Studio").unwrap());

        assert!(matches!(
            state.translate(RawBrowserEvent::Resolved(first)).unwrap(),
            DiscoveryBrowserEvent::Added(_)
        ));
        assert!(matches!(
            state.translate(RawBrowserEvent::Resolved(second)).unwrap(),
            DiscoveryBrowserEvent::Added(_)
        ));

        assert_eq!(state.peers.len(), 2);
        let first_peer = state
            .peers
            .get(&TransientDiscoveryKey::new(KEY).unwrap())
            .unwrap();
        let second_peer = state
            .peers
            .get(&TransientDiscoveryKey::new(OTHER_KEY).unwrap())
            .unwrap();
        assert_eq!(first_peer.metadata().name().unwrap().as_str(), "Studio");
        assert_eq!(second_peer.metadata().name().unwrap().as_str(), "Studio");
        assert_ne!(first_peer.key(), second_peer.key());
    }

    #[test]
    fn transient_service_keys_are_bounded_and_treated_as_untrusted_text() {
        assert_eq!(
            TransientDiscoveryKey::new("x".repeat(MAX_TRANSIENT_DISCOVERY_KEY_BYTES + 1))
                .unwrap_err()
                .kind(),
            DiscoveryBrowserErrorKind::InvalidTransientKey
        );
        assert_eq!(
            TransientDiscoveryKey::new("peer\n._local-transfer._tcp.local.")
                .unwrap_err()
                .kind(),
            DiscoveryBrowserErrorKind::InvalidTransientKey
        );
        assert_eq!(
            TransientDiscoveryKey::new("peer._other._tcp.local.")
                .unwrap_err()
                .kind(),
            DiscoveryBrowserErrorKind::InvalidTransientKey
        );
        assert_eq!(
            TransientDiscoveryKey::new("peer._LOCAL-TRANSFER._TCP.LOCAL.")
                .unwrap()
                .as_str(),
            "peer._local-transfer._tcp.local."
        );
    }

    #[test]
    fn removal_only_refers_to_a_previously_resolved_transient_key() {
        let mut state = BrowserState::default();
        state.translate(RawBrowserEvent::Resolved(resolved()));

        let event = state
            .translate(RawBrowserEvent::Removed(KEY.to_owned()))
            .unwrap();
        match event {
            DiscoveryBrowserEvent::Removed(key) => assert_eq!(key.as_str(), KEY),
            _ => panic!("expected removal"),
        }
        assert!(
            state
                .translate(RawBrowserEvent::Removed(KEY.to_owned()))
                .is_none()
        );
    }

    #[test]
    fn malformed_unsupported_and_incompatible_metadata_are_diagnostics() {
        let mut state = BrowserState::default();

        let mut missing = resolved();
        missing.txt.pop();
        assert_eq!(
            error_kind(state.translate(RawBrowserEvent::Resolved(missing)).unwrap()),
            DiscoveryBrowserErrorKind::Metadata
        );

        let mut unsupported = resolved();
        unsupported.txt[0] = DiscoveryTxtEntry::new("dv", "2").unwrap();
        assert_eq!(
            error_kind(
                state
                    .translate(RawBrowserEvent::Resolved(unsupported))
                    .unwrap()
            ),
            DiscoveryBrowserErrorKind::Metadata
        );

        let mut incompatible = resolved();
        incompatible.txt = txt_with_range(2, 2);
        assert_eq!(
            error_kind(
                state
                    .translate(RawBrowserEvent::Resolved(incompatible))
                    .unwrap()
            ),
            DiscoveryBrowserErrorKind::IncompatibleProtocol
        );
    }

    #[test]
    fn invalid_port_optional_hints_and_endpoint_rules_are_bounded() {
        let mut state = BrowserState::default();
        let mut invalid_port = resolved();
        invalid_port.port = 0;
        assert_eq!(
            error_kind(
                state
                    .translate(RawBrowserEvent::Resolved(invalid_port))
                    .unwrap()
            ),
            DiscoveryBrowserErrorKind::InvalidPort
        );

        let ipv4 = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let ipv6 = DiscoveryEndpoint::ipv6(Ipv6Addr::LOCALHOST, 4);
        let mut endpoints = resolved();
        endpoints.endpoints = vec![ipv4, ipv4, ipv6];
        endpoints
            .txt
            .push(DiscoveryTxtEntry::new("name", "\n").unwrap());
        endpoints
            .txt
            .push(DiscoveryTxtEntry::new("os", "plan9").unwrap());
        let peer = peer(
            state
                .translate(RawBrowserEvent::Resolved(endpoints))
                .unwrap(),
        );
        assert_eq!(peer.endpoints(), &[ipv4, ipv6]);
        assert_eq!(peer.metadata().name(), None);
        assert_eq!(peer.metadata().platform(), None);

        let mut too_many = resolved();
        too_many.endpoints = (1..=MAX_DISCOVERED_ENDPOINTS + 1)
            .map(|last| DiscoveryEndpoint::ipv4(Ipv4Addr::new(198, 51, 100, last as u8)))
            .collect();
        assert_eq!(
            error_kind(
                state
                    .translate(RawBrowserEvent::Resolved(too_many))
                    .unwrap()
            ),
            DiscoveryBrowserErrorKind::EndpointLimit
        );
    }

    #[test]
    fn transient_model_contains_only_advisory_resolution_data() {
        let metadata = DiscoveryMetadata::new(
            DiscoveryProtocolRange::initial(),
            Some(DiscoveryNameHint::new("Not identity").unwrap()),
            Some(DiscoveryPlatformHint::Linux),
        );
        let peer = peer(
            BrowserState::default()
                .translate(RawBrowserEvent::Resolved(RawResolvedService {
                    fullname: KEY.to_owned(),
                    port: 4242,
                    endpoints: vec![DiscoveryEndpoint::ipv4(Ipv4Addr::LOCALHOST)],
                    txt: metadata.to_txt_entries(),
                }))
                .unwrap(),
        );

        assert_eq!(peer.key().as_str(), KEY);
        assert_eq!(peer.metadata().name().unwrap().as_str(), "Not identity");
    }

    #[derive(Default)]
    struct FakeState {
        starts: usize,
        stops: usize,
        drops: usize,
        stop_error: Option<DiscoveryBrowserErrorKind>,
        events: VecDeque<RawBrowserEvent>,
    }

    struct FakeBackend(Rc<RefCell<FakeState>>);

    impl FakeBackend {
        fn start(
            state: Rc<RefCell<FakeState>>,
        ) -> impl FnOnce() -> Result<Self, DiscoveryBrowserError> {
            move || {
                state.borrow_mut().starts += 1;
                Ok(Self(state))
            }
        }
    }

    impl BrowserBackend for FakeBackend {
        fn poll_event(&mut self) -> Option<RawBrowserEvent> {
            self.0.borrow_mut().events.pop_front()
        }

        fn stop(&mut self) -> Result<(), DiscoveryBrowserError> {
            let mut state = self.0.borrow_mut();
            state.stops += 1;
            match state.stop_error {
                Some(kind) => Err(DiscoveryBrowserError::without_source(kind)),
                None => Ok(()),
            }
        }

        fn best_effort_stop(&mut self) {
            self.0.borrow_mut().drops += 1;
        }
    }

    #[test]
    fn session_lifecycle_and_backend_errors_are_deterministic() {
        let start_error = match BrowserSession::<FakeBackend>::start(|| {
            Err(DiscoveryBrowserError::without_source(
                DiscoveryBrowserErrorKind::Browse,
            ))
        }) {
            Ok(_) => panic!("browse start should fail"),
            Err(error) => error,
        };
        assert_eq!(start_error.kind(), DiscoveryBrowserErrorKind::Browse);

        let state = Rc::new(RefCell::new(FakeState::default()));
        state.borrow_mut().events.push_back(RawBrowserEvent::Error(
            DiscoveryBrowserError::without_source(DiscoveryBrowserErrorKind::Daemon),
        ));
        let mut session = BrowserSession::start(FakeBackend::start(state.clone())).unwrap();
        assert_eq!(
            error_kind(session.poll_event().unwrap()),
            DiscoveryBrowserErrorKind::Daemon
        );
        session.stop().unwrap();
        session.stop().unwrap();
        drop(session);
        let state = state.borrow();
        assert_eq!((state.starts, state.stops, state.drops), (1, 1, 0));
    }

    #[test]
    fn failed_stop_remains_active_for_best_effort_drop_cleanup() {
        for kind in [
            DiscoveryBrowserErrorKind::StopBrowse,
            DiscoveryBrowserErrorKind::Shutdown,
        ] {
            let state = Rc::new(RefCell::new(FakeState {
                stop_error: Some(kind),
                ..FakeState::default()
            }));
            let mut session = BrowserSession::start(FakeBackend::start(state.clone())).unwrap();
            assert_eq!(session.stop().unwrap_err().kind(), kind);
            drop(session);
            assert_eq!(state.borrow().drops, 1);
        }
    }

    fn seconds(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    fn assert_rejection(
        transition: &Option<DiscoveredPeerTransition>,
        expected: DiscoveryBrowserErrorKind,
    ) {
        match transition {
            Some(DiscoveredPeerTransition::Rejected(error)) => assert_eq!(error.kind(), expected),
            other => panic!("expected {expected:?} rejection, got {other:?}"),
        }
    }

    /// Drives a fake browser backend end to end into discovery lifecycle state.
    ///
    /// Every raw backend event is polled through a real [`BrowserSession`], and
    /// the translated browser event, when any, is applied to one
    /// [`DiscoveredPeerState`] at the caller-supplied time. No clock, sleep, or
    /// socket is involved, so the whole pipeline stays deterministic.
    fn run_discovery_pipeline(
        steps: Vec<(RawBrowserEvent, Duration)>,
    ) -> (DiscoveredPeerState, Vec<Option<DiscoveredPeerTransition>>) {
        let backend_state = Rc::new(RefCell::new(FakeState::default()));
        let times: Vec<Duration> = steps.iter().map(|(_, at)| *at).collect();
        {
            let mut queue = backend_state.borrow_mut();
            for (raw, _) in steps {
                queue.events.push_back(raw);
            }
        }

        let mut session = BrowserSession::start(FakeBackend::start(backend_state)).unwrap();
        let mut lifecycle = DiscoveredPeerState::new();
        let mut transitions = Vec::with_capacity(times.len());
        for observed_at in times {
            let transition = session
                .poll_event()
                .map(|event| lifecycle.apply(event, observed_at));
            transitions.push(transition);
        }

        assert!(
            session.poll_event().is_none(),
            "the fake backend queue must be fully drained"
        );
        session.stop().unwrap();
        (lifecycle, transitions)
    }

    #[test]
    fn browse_to_lifecycle_covers_appear_refresh_and_update() {
        let a = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let b = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 2));
        let c = DiscoveryEndpoint::ipv4(Ipv4Addr::new(192, 0, 2, 3));
        let with_endpoints = |endpoints: Vec<DiscoveryEndpoint>| {
            let mut resolution = resolved();
            resolution.endpoints = endpoints;
            resolution
        };
        let renamed = |endpoints: Vec<DiscoveryEndpoint>| {
            let mut resolution = with_endpoints(endpoints);
            resolution
                .txt
                .push(DiscoveryTxtEntry::new("name", "Kitchen").unwrap());
            resolution
        };

        let (state, transitions) = run_discovery_pipeline(vec![
            (
                RawBrowserEvent::Resolved(with_endpoints(vec![a, b])),
                seconds(1),
            ),
            (
                RawBrowserEvent::Resolved(with_endpoints(vec![a, b])),
                seconds(3),
            ),
            (
                RawBrowserEvent::Resolved(with_endpoints(vec![b, a, a, b])),
                seconds(5),
            ),
            (
                RawBrowserEvent::Resolved(with_endpoints(vec![b, c])),
                seconds(7),
            ),
            (RawBrowserEvent::Resolved(renamed(vec![b, c])), seconds(9)),
        ]);

        assert!(matches!(
            transitions.as_slice(),
            [
                Some(DiscoveredPeerTransition::Appeared(_)),
                Some(DiscoveredPeerTransition::Refreshed(_)),
                Some(DiscoveredPeerTransition::Refreshed(_)),
                Some(DiscoveredPeerTransition::Updated(_)),
                Some(DiscoveredPeerTransition::Updated(_)),
            ]
        ));
        assert_eq!(state.len(), 1);
        let peer = state
            .get(&TransientDiscoveryKey::new(KEY).unwrap())
            .unwrap();
        assert_eq!(peer.endpoints(), &[b, c]);
        assert_eq!(peer.metadata().name().unwrap().as_str(), "Kitchen");
    }

    #[test]
    fn browse_to_lifecycle_expiry_uses_caller_supplied_time() {
        let (mut state, transitions) = run_discovery_pipeline(vec![
            (RawBrowserEvent::Resolved(resolved()), seconds(1)),
            (RawBrowserEvent::Resolved(resolved()), seconds(8)),
        ]);

        assert!(matches!(
            transitions.as_slice(),
            [
                Some(DiscoveredPeerTransition::Appeared(_)),
                Some(DiscoveredPeerTransition::Refreshed(_)),
            ]
        ));
        assert_eq!(state.len(), 1);

        // The refresh advanced liveness to t=8, so t=12 is only four seconds stale.
        assert!(state.expire(seconds(12), seconds(5)).is_empty());
        assert_eq!(state.len(), 1);

        let expired = state.expire(seconds(14), seconds(5));
        assert!(matches!(
            expired.as_slice(),
            [DiscoveredPeerTransition::Removed {
                reason: DiscoveredPeerRemovalReason::Expired,
                ..
            }]
        ));
        assert!(state.is_empty());

        // Expiring already-absent state stays a deterministic no-op.
        assert!(state.expire(seconds(99), seconds(1)).is_empty());
        assert!(state.is_empty());
    }

    #[test]
    fn browse_to_lifecycle_removal_absent_and_stale_are_deterministic() {
        let (state, transitions) = run_discovery_pipeline(vec![
            // Removal of a never-seen advertisement produces no browser event at all.
            (RawBrowserEvent::Removed(KEY.to_owned()), seconds(1)),
            // Normal appearance and explicit removal.
            (RawBrowserEvent::Resolved(resolved()), seconds(5)),
            (RawBrowserEvent::Removed(KEY.to_owned()), seconds(8)),
            // A second removal is coalesced away by the browser before lifecycle state.
            (RawBrowserEvent::Removed(KEY.to_owned()), seconds(9)),
            // An observation that predates the removal cannot resurrect the peer.
            (RawBrowserEvent::Resolved(resolved()), seconds(7)),
            // A later observation makes the transient advertisement visible again.
            (RawBrowserEvent::Resolved(resolved()), seconds(12)),
        ]);

        assert!(matches!(
            transitions.as_slice(),
            [
                None,
                Some(DiscoveredPeerTransition::Appeared(_)),
                Some(DiscoveredPeerTransition::Removed {
                    reason: DiscoveredPeerRemovalReason::Explicit,
                    ..
                }),
                None,
                Some(DiscoveredPeerTransition::Noop {
                    reason: DiscoveredPeerNoopReason::Stale,
                    ..
                }),
                Some(DiscoveredPeerTransition::Appeared(_)),
            ]
        ));
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn browse_to_lifecycle_rejects_invalid_observations_without_touching_visible_state() {
        let missing_schema = || {
            let mut resolution = resolved();
            resolution.txt.remove(0); // drop the required `dv` entry
            resolution
        };
        let unsupported_schema = || {
            let mut resolution = resolved();
            resolution.txt[0] = DiscoveryTxtEntry::new("dv", "2").unwrap();
            resolution
        };
        let incompatible_protocol = || {
            let mut resolution = resolved();
            resolution.txt = txt_with_range(2, 2);
            resolution
        };
        let zero_port = || {
            let mut resolution = resolved();
            resolution.port = 0;
            resolution
        };
        let too_many_endpoints = || {
            let mut resolution = resolved();
            resolution.endpoints = (1..=MAX_DISCOVERED_ENDPOINTS + 1)
                .map(|last| DiscoveryEndpoint::ipv4(Ipv4Addr::new(198, 51, 100, last as u8)))
                .collect();
            resolution
        };

        let (mut state, transitions) = run_discovery_pipeline(vec![
            (RawBrowserEvent::Resolved(resolved()), seconds(1)),
            (RawBrowserEvent::Resolved(missing_schema()), seconds(2)),
            (RawBrowserEvent::Resolved(unsupported_schema()), seconds(3)),
            (
                RawBrowserEvent::Resolved(incompatible_protocol()),
                seconds(4),
            ),
            (RawBrowserEvent::Resolved(zero_port()), seconds(5)),
            (RawBrowserEvent::Resolved(too_many_endpoints()), seconds(6)),
        ]);

        assert!(matches!(
            &transitions[0],
            Some(DiscoveredPeerTransition::Appeared(_))
        ));
        assert_rejection(&transitions[1], DiscoveryBrowserErrorKind::Metadata);
        assert_rejection(&transitions[2], DiscoveryBrowserErrorKind::Metadata);
        assert_rejection(
            &transitions[3],
            DiscoveryBrowserErrorKind::IncompatibleProtocol,
        );
        assert_rejection(&transitions[4], DiscoveryBrowserErrorKind::InvalidPort);
        assert_rejection(&transitions[5], DiscoveryBrowserErrorKind::EndpointLimit);

        assert_eq!(state.len(), 1);
        // Liveness never advanced past the only valid observation at t=1.
        let expired = state.expire(seconds(10), seconds(9));
        assert!(matches!(
            expired.as_slice(),
            [DiscoveredPeerTransition::Removed {
                reason: DiscoveredPeerRemovalReason::Expired,
                ..
            }]
        ));
        assert!(state.is_empty());
    }

    #[test]
    fn browse_to_lifecycle_keeps_same_name_advertisements_distinct() {
        const KEY_TWO: &str = "lt-second._local-transfer._tcp.local.";
        let named = |fullname: &str, last_octet: u8| {
            let mut resolution = resolved();
            resolution.fullname = fullname.to_owned();
            resolution.endpoints = vec![DiscoveryEndpoint::ipv4(Ipv4Addr::new(
                192, 0, 2, last_octet,
            ))];
            resolution
                .txt
                .push(DiscoveryTxtEntry::new("name", "Studio").unwrap());
            resolution
        };

        let (state, transitions) = run_discovery_pipeline(vec![
            (RawBrowserEvent::Resolved(named(KEY, 1)), seconds(1)),
            (RawBrowserEvent::Resolved(named(KEY_TWO, 2)), seconds(1)),
        ]);

        assert!(matches!(
            transitions.as_slice(),
            [
                Some(DiscoveredPeerTransition::Appeared(_)),
                Some(DiscoveredPeerTransition::Appeared(_)),
            ]
        ));
        assert_eq!(state.len(), 2);
        let first = state
            .get(&TransientDiscoveryKey::new(KEY).unwrap())
            .unwrap();
        let second = state
            .get(&TransientDiscoveryKey::new(KEY_TWO).unwrap())
            .unwrap();
        assert_eq!(first.metadata().name().unwrap().as_str(), "Studio");
        assert_eq!(second.metadata().name().unwrap().as_str(), "Studio");
        assert_ne!(first.key(), second.key());
    }

    #[test]
    fn browse_to_lifecycle_propagates_typed_adapter_failure() {
        let (mut state, transitions) = run_discovery_pipeline(vec![
            (RawBrowserEvent::Resolved(resolved()), seconds(1)),
            (
                RawBrowserEvent::Error(DiscoveryBrowserError::without_source(
                    DiscoveryBrowserErrorKind::Daemon,
                )),
                seconds(2),
            ),
        ]);

        assert!(matches!(
            &transitions[0],
            Some(DiscoveredPeerTransition::Appeared(_))
        ));
        assert_rejection(&transitions[1], DiscoveryBrowserErrorKind::Daemon);

        assert_eq!(state.len(), 1);
        // The adapter failure did not refresh the visible peer.
        let expired = state.expire(seconds(11), seconds(10));
        assert!(matches!(
            expired.as_slice(),
            [DiscoveredPeerTransition::Removed {
                reason: DiscoveredPeerRemovalReason::Expired,
                ..
            }]
        ));
        assert!(state.is_empty());
    }
}
