//! DNS-SD advertisement lifecycle built on the bounded discovery contract.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use mdns_sd::{DaemonEvent, DaemonStatus, ServiceDaemon, ServiceInfo, UnregisterStatus};
use uuid::Uuid;

use crate::discovery::{DISCOVERY_SERVICE_TYPE, DiscoveryMetadata, MAX_DISCOVERY_TXT_BYTES};

const LOCAL_DOMAIN_SUFFIX: &str = ".local.";
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration for one local DNS-SD advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryAdvertisementConfig {
    metadata: DiscoveryMetadata,
    port: u16,
}

impl DiscoveryAdvertisementConfig {
    /// Creates an advertisement configuration with a caller-owned TCP port.
    pub fn new(
        metadata: DiscoveryMetadata,
        port: u16,
    ) -> Result<Self, DiscoveryAdvertisementError> {
        if port == 0 {
            return Err(DiscoveryAdvertisementError::without_source(
                DiscoveryAdvertisementErrorKind::InvalidPort,
            ));
        }
        Ok(Self { metadata, port })
    }

    /// Returns the validated discovery metadata to advertise.
    #[must_use]
    pub const fn metadata(&self) -> &DiscoveryMetadata {
        &self.metadata
    }

    /// Returns the non-zero TCP service port supplied by the caller.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// The stage at which a discovery advertisement operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryAdvertisementErrorKind {
    /// TCP port zero was supplied.
    InvalidPort,
    /// Validated metadata could not be represented safely as TXT properties.
    MetadataEncoding,
    /// The mDNS daemon could not be created.
    DaemonStartup,
    /// The DNS-SD service description could not be constructed.
    ServiceConstruction,
    /// The daemon rejected the registration request.
    Registration,
    /// The daemon reported a later asynchronous failure.
    Daemon,
    /// Graceful service unregistration failed.
    Unregister,
    /// Graceful daemon shutdown failed.
    Shutdown,
}

/// A focused error boundary that hides infrastructure types while preserving causes.
#[derive(Debug)]
pub struct DiscoveryAdvertisementError {
    kind: DiscoveryAdvertisementErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl DiscoveryAdvertisementError {
    /// Returns the operation category.
    #[must_use]
    pub const fn kind(&self) -> DiscoveryAdvertisementErrorKind {
        self.kind
    }

    fn without_source(kind: DiscoveryAdvertisementErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn with_source(
        kind: DiscoveryAdvertisementErrorKind,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for DiscoveryAdvertisementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            DiscoveryAdvertisementErrorKind::InvalidPort => {
                "discovery advertisement port must not be zero"
            }
            DiscoveryAdvertisementErrorKind::MetadataEncoding => {
                "discovery metadata could not be encoded safely"
            }
            DiscoveryAdvertisementErrorKind::DaemonStartup => {
                "failed to start the mDNS advertisement daemon"
            }
            DiscoveryAdvertisementErrorKind::ServiceConstruction => {
                "failed to construct the DNS-SD service"
            }
            DiscoveryAdvertisementErrorKind::Registration => {
                "failed to submit the DNS-SD registration"
            }
            DiscoveryAdvertisementErrorKind::Daemon => {
                "the mDNS advertisement daemon reported an error"
            }
            DiscoveryAdvertisementErrorKind::Unregister => {
                "failed to unregister the DNS-SD service"
            }
            DiscoveryAdvertisementErrorKind::Shutdown => {
                "failed to shut down the mDNS advertisement daemon"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for DiscoveryAdvertisementError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// A noteworthy asynchronous event from an active advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryAdvertisementEvent {
    /// Standards-based conflict resolution changed an ephemeral DNS name.
    NameChanged {
        /// The originally requested ephemeral name.
        original: String,
        /// The replacement name selected by the mDNS implementation.
        replacement: String,
    },
}

/// An owned DNS-SD advertisement session.
///
/// `start` means daemon creation succeeded and the registration command was
/// accepted; actual multicast transmission happens asynchronously. Call
/// [`poll_event`](Self::poll_event) to surface later daemon errors and name
/// conflicts. Explicit [`stop`](Self::stop) is the authoritative cleanup path.
pub struct DiscoveryAdvertisement {
    session: AdvertisementSession<MdnsBackend>,
}

impl DiscoveryAdvertisement {
    /// Starts advertising with a fresh, non-persistent random session identity.
    pub fn start(
        config: DiscoveryAdvertisementConfig,
    ) -> Result<Self, DiscoveryAdvertisementError> {
        let spec = ServiceSpec::new(config, SessionIdentity::random())?;
        let session = AdvertisementSession::start(spec, MdnsBackend::start)?;
        Ok(Self { session })
    }

    /// Returns the requested ephemeral DNS-SD instance label for this session.
    #[must_use]
    pub fn instance_name(&self) -> &str {
        &self.session.spec.instance_name
    }

    /// Returns the requested ephemeral `.local.` hostname for this session.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.session.spec.hostname
    }

    /// Non-blockingly reports the next relevant daemon event, if any.
    pub fn poll_event(
        &mut self,
    ) -> Result<Option<DiscoveryAdvertisementEvent>, DiscoveryAdvertisementError> {
        self.session.backend.poll_event()
    }

    /// Gracefully unregisters the service and shuts down its daemon.
    ///
    /// This method waits for each acknowledgement for at most two seconds.
    /// Repeated calls after a successful stop are harmless.
    pub fn stop(&mut self) -> Result<(), DiscoveryAdvertisementError> {
        self.session.stop()
    }
}

impl fmt::Debug for DiscoveryAdvertisement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryAdvertisement")
            .field("instance_name", &self.instance_name())
            .field("hostname", &self.hostname())
            .field("active", &self.session.active)
            .finish_non_exhaustive()
    }
}

struct ServiceSpec {
    service_type: String,
    instance_name: String,
    hostname: String,
    port: u16,
    properties: HashMap<String, String>,
}

impl ServiceSpec {
    fn new(
        config: DiscoveryAdvertisementConfig,
        identity: SessionIdentity,
    ) -> Result<Self, DiscoveryAdvertisementError> {
        let entries = config.metadata.to_txt_entries();
        let total = entries.iter().fold(0_usize, |total, entry| {
            total.saturating_add(entry.encoded_size())
        });
        if total > MAX_DISCOVERY_TXT_BYTES {
            return Err(DiscoveryAdvertisementError::without_source(
                DiscoveryAdvertisementErrorKind::MetadataEncoding,
            ));
        }

        let properties = entries
            .into_iter()
            .map(|entry| {
                let value = String::from_utf8(entry.value().to_vec()).map_err(|source| {
                    DiscoveryAdvertisementError::with_source(
                        DiscoveryAdvertisementErrorKind::MetadataEncoding,
                        source,
                    )
                })?;
                Ok((entry.key().to_owned(), value))
            })
            .collect::<Result<_, DiscoveryAdvertisementError>>()?;

        Ok(Self {
            service_type: format!("{DISCOVERY_SERVICE_TYPE}{LOCAL_DOMAIN_SUFFIX}"),
            instance_name: identity.label.clone(),
            hostname: format!("{}{LOCAL_DOMAIN_SUFFIX}", identity.label),
            port: config.port,
            properties,
        })
    }

    fn fullname(&self) -> String {
        format!("{}.{}", self.instance_name, self.service_type)
    }
}

struct SessionIdentity {
    label: String,
}

impl SessionIdentity {
    fn random() -> Self {
        Self {
            label: format!("lt-{}", Uuid::new_v4()),
        }
    }

    #[cfg(test)]
    fn fixed(suffix: &str) -> Self {
        Self {
            label: format!("lt-{suffix}"),
        }
    }
}

trait AdvertisementBackend {
    fn stop(&mut self) -> Result<(), DiscoveryAdvertisementError>;
    fn best_effort_stop(&mut self);
}

struct AdvertisementSession<B: AdvertisementBackend> {
    spec: ServiceSpec,
    backend: B,
    active: bool,
}

impl<B: AdvertisementBackend> AdvertisementSession<B> {
    fn start(
        spec: ServiceSpec,
        start_backend: impl FnOnce(&ServiceSpec) -> Result<B, DiscoveryAdvertisementError>,
    ) -> Result<Self, DiscoveryAdvertisementError> {
        let backend = start_backend(&spec)?;
        Ok(Self {
            spec,
            backend,
            active: true,
        })
    }

    fn stop(&mut self) -> Result<(), DiscoveryAdvertisementError> {
        if !self.active {
            return Ok(());
        }
        self.backend.stop()?;
        self.active = false;
        Ok(())
    }
}

impl<B: AdvertisementBackend> Drop for AdvertisementSession<B> {
    fn drop(&mut self) {
        if self.active {
            self.backend.best_effort_stop();
        }
    }
}

struct MdnsBackend {
    daemon: ServiceDaemon,
    events: mdns_sd::Receiver<DaemonEvent>,
    fullname: String,
}

impl MdnsBackend {
    fn start(spec: &ServiceSpec) -> Result<Self, DiscoveryAdvertisementError> {
        let service = build_service_info(spec)?;
        let daemon = ServiceDaemon::new().map_err(|source| {
            DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::DaemonStartup,
                source,
            )
        })?;
        let events = daemon.monitor().map_err(|source| {
            let _ = daemon.shutdown();
            DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::DaemonStartup,
                source,
            )
        })?;
        daemon.register(service).map_err(|source| {
            let _ = daemon.shutdown();
            DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::Registration,
                source,
            )
        })?;
        Ok(Self {
            daemon,
            events,
            fullname: spec.fullname(),
        })
    }

    fn poll_event(
        &mut self,
    ) -> Result<Option<DiscoveryAdvertisementEvent>, DiscoveryAdvertisementError> {
        loop {
            match self.events.try_recv() {
                Ok(DaemonEvent::Error(source)) => {
                    return Err(DiscoveryAdvertisementError::with_source(
                        DiscoveryAdvertisementErrorKind::Daemon,
                        source,
                    ));
                }
                Ok(DaemonEvent::NameChange(change)) => {
                    return Ok(Some(DiscoveryAdvertisementEvent::NameChanged {
                        original: change.original,
                        replacement: change.new_name,
                    }));
                }
                Ok(_) => {}
                Err(mdns_sd::TryRecvError::Empty) => return Ok(None),
                Err(source) => {
                    return Err(DiscoveryAdvertisementError::with_source(
                        DiscoveryAdvertisementErrorKind::Daemon,
                        source,
                    ));
                }
            }
        }
    }
}

impl AdvertisementBackend for MdnsBackend {
    fn stop(&mut self) -> Result<(), DiscoveryAdvertisementError> {
        let unregister_result = self.unregister();
        let shutdown_result = self.shutdown();
        unregister_result.and(shutdown_result)
    }

    fn best_effort_stop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

impl MdnsBackend {
    fn unregister(&self) -> Result<(), DiscoveryAdvertisementError> {
        let receiver = self.daemon.unregister(&self.fullname).map_err(|source| {
            DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::Unregister,
                source,
            )
        })?;
        match receiver.recv_timeout(STOP_TIMEOUT) {
            Ok(UnregisterStatus::OK | UnregisterStatus::NotFound) => Ok(()),
            Err(source) => Err(DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::Unregister,
                source,
            )),
        }
    }

    fn shutdown(&self) -> Result<(), DiscoveryAdvertisementError> {
        let receiver = self.daemon.shutdown().map_err(|source| {
            DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::Shutdown,
                source,
            )
        })?;
        match receiver.recv_timeout(STOP_TIMEOUT) {
            Ok(DaemonStatus::Shutdown) => Ok(()),
            Ok(_) => Err(DiscoveryAdvertisementError::without_source(
                DiscoveryAdvertisementErrorKind::Shutdown,
            )),
            Err(source) => Err(DiscoveryAdvertisementError::with_source(
                DiscoveryAdvertisementErrorKind::Shutdown,
                source,
            )),
        }
    }
}

fn build_service_info(spec: &ServiceSpec) -> Result<ServiceInfo, DiscoveryAdvertisementError> {
    ServiceInfo::new(
        &spec.service_type,
        &spec.instance_name,
        &spec.hostname,
        (),
        spec.port,
        spec.properties.clone(),
    )
    .map(ServiceInfo::enable_addr_auto)
    .map_err(|source| {
        DiscoveryAdvertisementError::with_source(
            DiscoveryAdvertisementErrorKind::ServiceConstruction,
            source,
        )
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::{
        AdvertisementBackend, AdvertisementSession, DiscoveryAdvertisementConfig,
        DiscoveryAdvertisementError, DiscoveryAdvertisementErrorKind, ServiceSpec, SessionIdentity,
        build_service_info,
    };
    use crate::discovery::{
        DISCOVERY_SERVICE_TYPE, DiscoveryMetadata, DiscoveryNameHint, DiscoveryPlatformHint,
        DiscoveryProtocolRange,
    };

    fn metadata() -> DiscoveryMetadata {
        DiscoveryMetadata::new(
            DiscoveryProtocolRange::initial(),
            Some(DiscoveryNameHint::new("Living Room").unwrap()),
            Some(DiscoveryPlatformHint::Linux),
        )
    }

    fn spec(suffix: &str) -> ServiceSpec {
        ServiceSpec::new(
            DiscoveryAdvertisementConfig::new(metadata(), 4242).unwrap(),
            SessionIdentity::fixed(suffix),
        )
        .unwrap()
    }

    #[test]
    fn port_zero_is_rejected_before_service_construction() {
        let error = DiscoveryAdvertisementConfig::new(metadata(), 0).unwrap_err();
        assert_eq!(error.kind(), DiscoveryAdvertisementErrorKind::InvalidPort);
    }

    #[test]
    fn service_uses_ephemeral_names_auto_addresses_and_only_schema_txt() {
        let spec = spec("00112233-4455-4677-8899-aabbccddeeff");
        let service = build_service_info(&spec).unwrap();

        assert_eq!(
            spec.service_type,
            format!("{DISCOVERY_SERVICE_TYPE}.local.")
        );
        assert_eq!(
            spec.instance_name,
            "lt-00112233-4455-4677-8899-aabbccddeeff"
        );
        assert_eq!(
            spec.hostname,
            "lt-00112233-4455-4677-8899-aabbccddeeff.local."
        );
        assert_eq!(service.get_port(), 4242);
        assert!(service.is_addr_auto());
        assert!(service.get_addresses().is_empty());
        assert_eq!(spec.properties.len(), 5);
        for key in ["dv", "pmin", "pmax", "name", "os"] {
            assert!(spec.properties.contains_key(key));
        }
    }

    #[test]
    fn independent_sessions_receive_distinct_dns_safe_bounded_names() {
        let first = SessionIdentity::random();
        let second = SessionIdentity::random();

        assert_ne!(first.label, second.label);
        for label in [first.label, second.label] {
            assert!(label.starts_with("lt-"));
            assert!(label.len() <= 63);
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            );
        }
    }

    #[derive(Default)]
    struct State {
        starts: usize,
        stops: usize,
        drops: usize,
        fail_start: bool,
        stop_error: Option<DiscoveryAdvertisementErrorKind>,
    }

    struct FakeBackend(Rc<RefCell<State>>);

    impl FakeBackend {
        fn start(
            state: Rc<RefCell<State>>,
        ) -> impl FnOnce(&ServiceSpec) -> Result<Self, DiscoveryAdvertisementError> {
            move |_| {
                let mut state_ref = state.borrow_mut();
                state_ref.starts += 1;
                if state_ref.fail_start {
                    return Err(DiscoveryAdvertisementError::without_source(
                        DiscoveryAdvertisementErrorKind::Registration,
                    ));
                }
                drop(state_ref);
                Ok(Self(state))
            }
        }
    }

    impl AdvertisementBackend for FakeBackend {
        fn stop(&mut self) -> Result<(), DiscoveryAdvertisementError> {
            let mut state = self.0.borrow_mut();
            state.stops += 1;
            if let Some(kind) = state.stop_error {
                return Err(DiscoveryAdvertisementError::without_source(kind));
            }
            Ok(())
        }

        fn best_effort_stop(&mut self) {
            self.0.borrow_mut().drops += 1;
        }
    }

    #[test]
    fn start_and_stop_lifecycle_is_owned_and_idempotent() {
        let state = Rc::new(RefCell::new(State::default()));
        let mut session =
            AdvertisementSession::start(spec("session"), FakeBackend::start(state.clone()))
                .unwrap();

        session.stop().unwrap();
        session.stop().unwrap();
        drop(session);

        let state = state.borrow();
        assert_eq!(state.starts, 1);
        assert_eq!(state.stops, 1);
        assert_eq!(state.drops, 0);
    }

    #[test]
    fn registration_unregister_and_shutdown_errors_remain_typed() {
        let start_state = Rc::new(RefCell::new(State {
            fail_start: true,
            ..State::default()
        }));
        let start_error =
            match AdvertisementSession::start(spec("start-error"), FakeBackend::start(start_state))
            {
                Ok(_) => panic!("registration should fail"),
                Err(error) => error,
            };
        assert_eq!(
            start_error.kind(),
            DiscoveryAdvertisementErrorKind::Registration
        );

        for kind in [
            DiscoveryAdvertisementErrorKind::Unregister,
            DiscoveryAdvertisementErrorKind::Shutdown,
        ] {
            let stop_state = Rc::new(RefCell::new(State {
                stop_error: Some(kind),
                ..State::default()
            }));
            let mut session = AdvertisementSession::start(
                spec("stop-error"),
                FakeBackend::start(stop_state.clone()),
            )
            .unwrap();
            let stop_error = session.stop().unwrap_err();
            assert_eq!(stop_error.kind(), kind);
            drop(session);
            assert_eq!(stop_state.borrow().drops, 1);
        }
    }

    #[test]
    fn active_drop_requests_non_blocking_best_effort_cleanup() {
        let state = Rc::new(RefCell::new(State::default()));
        let session =
            AdvertisementSession::start(spec("drop"), FakeBackend::start(state.clone())).unwrap();

        drop(session);

        let state = state.borrow();
        assert_eq!(state.stops, 0);
        assert_eq!(state.drops, 1);
    }
}
