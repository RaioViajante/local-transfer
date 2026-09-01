//! Bounded, unauthenticated metadata for DNS-SD discovery.

use std::error::Error;
use std::fmt;
use std::str;

use crate::device_name::DeviceName;
use crate::platform::Platform;

/// The canonical DNS-SD service type for local-transfer.
pub const DISCOVERY_SERVICE_TYPE: &str = "_local-transfer._tcp";
/// The discovery metadata schema version emitted and accepted by this release.
pub const DISCOVERY_SCHEMA_VERSION: u16 = 1;
/// The initial local-transfer application protocol major version.
pub const INITIAL_PROTOCOL_MAJOR: u16 = 1;
/// The maximum encoded UTF-8 size of the optional `name` hint.
pub const MAX_DISCOVERY_NAME_BYTES: usize = 96;
/// The maximum encoded size of all local-transfer TXT entries, including length octets.
pub const MAX_DISCOVERY_TXT_BYTES: usize = 512;
/// The DNS-SD maximum payload size of one length-prefixed TXT entry.
pub const MAX_DISCOVERY_TXT_ENTRY_BYTES: usize = 255;

const KEY_DISCOVERY_VERSION: &str = "dv";
const KEY_PROTOCOL_MIN: &str = "pmin";
const KEY_PROTOCOL_MAX: &str = "pmax";
const KEY_NAME: &str = "name";
const KEY_PLATFORM: &str = "os";

/// An inclusive range of supported application protocol major versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryProtocolRange {
    min: u16,
    max: u16,
}

impl DiscoveryProtocolRange {
    /// Creates a non-empty inclusive protocol-major range.
    pub fn new(min: u16, max: u16) -> Result<Self, DiscoveryProtocolRangeError> {
        if min > max {
            return Err(DiscoveryProtocolRangeError { min, max });
        }
        Ok(Self { min, max })
    }

    /// Returns the initial supported application protocol range, `1..=1`.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            min: INITIAL_PROTOCOL_MAJOR,
            max: INITIAL_PROTOCOL_MAJOR,
        }
    }

    /// Returns the minimum supported protocol major version.
    #[must_use]
    pub const fn min(self) -> u16 {
        self.min
    }

    /// Returns the maximum supported protocol major version.
    #[must_use]
    pub const fn max(self) -> u16 {
        self.max
    }

    /// Returns the highest protocol major version supported by both ranges.
    #[must_use]
    pub fn highest_compatible_version(self, other: Self) -> Option<u16> {
        let minimum = self.min.max(other.min);
        let maximum = self.max.min(other.max);
        (minimum <= maximum).then_some(maximum)
    }

    /// Reports whether the ranges share at least one protocol major version.
    #[must_use]
    pub fn is_compatible_with(self, other: Self) -> bool {
        self.highest_compatible_version(other).is_some()
    }
}

/// A protocol-major range has its minimum above its maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryProtocolRangeError {
    min: u16,
    max: u16,
}

impl DiscoveryProtocolRangeError {
    /// Returns the invalid minimum.
    #[must_use]
    pub const fn min(self) -> u16 {
        self.min
    }

    /// Returns the invalid maximum.
    #[must_use]
    pub const fn max(self) -> u16 {
        self.max
    }
}

impl fmt::Display for DiscoveryProtocolRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "minimum protocol major {} exceeds maximum {}",
            self.min, self.max
        )
    }
}

impl Error for DiscoveryProtocolRangeError {}

/// A bounded, non-authoritative UTF-8 device-name hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryNameHint(String);

impl DiscoveryNameHint {
    /// Validates an optional presentation hint without treating it as identity.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DiscoveryNameHintError> {
        let value = value.as_ref();
        if value.len() > MAX_DISCOVERY_NAME_BYTES {
            return Err(DiscoveryNameHintError::TooLong {
                actual: value.len(),
                maximum: MAX_DISCOVERY_NAME_BYTES,
            });
        }
        if value.trim().is_empty() {
            return Err(DiscoveryNameHintError::Empty);
        }
        if value.chars().any(char::is_control) {
            return Err(DiscoveryNameHintError::ControlCharacter);
        }
        Ok(Self(value.to_owned()))
    }

    /// Derives a hint from a validated name, truncating only at a UTF-8 boundary.
    #[must_use]
    pub fn from_device_name(name: &DeviceName) -> Self {
        let value = name.as_str();
        let mut end = value.len().min(MAX_DISCOVERY_NAME_BYTES);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        Self(value[..end].to_owned())
    }

    /// Returns the advisory name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A local discovery-name hint is not safe to advertise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryNameHintError {
    /// The hint contains no visible text.
    Empty,
    /// The hint contains a control character.
    ControlCharacter,
    /// The encoded hint exceeds the discovery budget.
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for DiscoveryNameHintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("discovery name hint must not be empty"),
            Self::ControlCharacter => {
                formatter.write_str("discovery name hint must not contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "discovery name hint is {actual} UTF-8 bytes; maximum is {maximum}"
            ),
        }
    }
}

impl Error for DiscoveryNameHintError {}

/// Bounded, non-authoritative operating-system presentation metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPlatformHint {
    /// Apple macOS.
    MacOs,
    /// Microsoft Windows.
    Windows,
    /// Linux.
    Linux,
}

impl DiscoveryPlatformHint {
    /// Returns the documented TXT representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"macos" => Some(Self::MacOs),
            b"windows" => Some(Self::Windows),
            b"linux" => Some(Self::Linux),
            _ => None,
        }
    }
}

impl From<Platform> for DiscoveryPlatformHint {
    fn from(platform: Platform) -> Self {
        match platform {
            Platform::MacOs => Self::MacOs,
            Platform::Windows => Self::Windows,
            Platform::Linux => Self::Linux,
        }
    }
}

/// One adapter-neutral DNS-SD TXT key/value entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryTxtEntry {
    key: String,
    value: Vec<u8>,
}

impl DiscoveryTxtEntry {
    /// Validates a TXT entry's key syntax and DNS-SD per-entry size limit.
    pub fn new(
        key: impl AsRef<str>,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, DiscoveryMetadataError> {
        let key = key.as_ref();
        let value = value.as_ref();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'=')
        {
            return Err(DiscoveryMetadataError::InvalidTxtKey);
        }
        let size = key.len().saturating_add(1).saturating_add(value.len());
        if size > MAX_DISCOVERY_TXT_ENTRY_BYTES {
            return Err(DiscoveryMetadataError::TxtEntryTooLarge {
                size,
                maximum: MAX_DISCOVERY_TXT_ENTRY_BYTES,
            });
        }
        Ok(Self {
            key: key.to_owned(),
            value: value.to_vec(),
        })
    }

    /// Returns the entry key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the entry's untrusted value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    fn encoded_size(&self) -> usize {
        1 + self.key.len() + 1 + self.value.len()
    }

    fn emitted(key: &'static str, value: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.to_owned(),
            value: value.into(),
        }
    }
}

/// Validated discovery schema v1 metadata from an unauthenticated peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryMetadata {
    protocols: DiscoveryProtocolRange,
    name: Option<DiscoveryNameHint>,
    platform: Option<DiscoveryPlatformHint>,
}

impl DiscoveryMetadata {
    /// Creates local schema v1 metadata from bounded domain values.
    #[must_use]
    pub const fn new(
        protocols: DiscoveryProtocolRange,
        name: Option<DiscoveryNameHint>,
        platform: Option<DiscoveryPlatformHint>,
    ) -> Self {
        Self {
            protocols,
            name,
            platform,
        }
    }

    /// Returns the discovery schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        DISCOVERY_SCHEMA_VERSION
    }

    /// Returns the peer's inclusive application-protocol range.
    #[must_use]
    pub const fn protocols(&self) -> DiscoveryProtocolRange {
        self.protocols
    }

    /// Returns the optional, non-authoritative name hint.
    #[must_use]
    pub fn name(&self) -> Option<&DiscoveryNameHint> {
        self.name.as_ref()
    }

    /// Returns the optional, non-authoritative platform hint.
    #[must_use]
    pub const fn platform(&self) -> Option<DiscoveryPlatformHint> {
        self.platform
    }

    /// Emits only the five documented schema keys in canonical form.
    #[must_use]
    pub fn to_txt_entries(&self) -> Vec<DiscoveryTxtEntry> {
        let mut entries = vec![
            DiscoveryTxtEntry::emitted(
                KEY_DISCOVERY_VERSION,
                DISCOVERY_SCHEMA_VERSION.to_string().into_bytes(),
            ),
            DiscoveryTxtEntry::emitted(
                KEY_PROTOCOL_MIN,
                self.protocols.min.to_string().into_bytes(),
            ),
            DiscoveryTxtEntry::emitted(
                KEY_PROTOCOL_MAX,
                self.protocols.max.to_string().into_bytes(),
            ),
        ];
        if let Some(name) = &self.name {
            entries.push(DiscoveryTxtEntry::emitted(
                KEY_NAME,
                name.as_str().as_bytes().to_vec(),
            ));
        }
        if let Some(platform) = self.platform {
            entries.push(DiscoveryTxtEntry::emitted(
                KEY_PLATFORM,
                platform.as_str().as_bytes().to_vec(),
            ));
        }
        entries
    }

    /// Parses bounded untrusted TXT entries.
    ///
    /// Required compatibility fields are strict. Invalid optional presentation
    /// values are discarded. Unknown keys are ignored after size validation.
    pub fn from_txt_entries(entries: &[DiscoveryTxtEntry]) -> Result<Self, DiscoveryMetadataError> {
        let total_size = entries.iter().fold(0_usize, |total, entry| {
            total.saturating_add(entry.encoded_size())
        });
        if total_size > MAX_DISCOVERY_TXT_BYTES {
            return Err(DiscoveryMetadataError::TotalMetadataTooLarge {
                size: total_size,
                maximum: MAX_DISCOVERY_TXT_BYTES,
            });
        }

        let mut discovery_version = None;
        let mut protocol_min = None;
        let mut protocol_max = None;
        let mut name = None;
        let mut platform = None;
        for entry in entries {
            if entry.key.eq_ignore_ascii_case(KEY_DISCOVERY_VERSION) {
                set_once(&mut discovery_version, entry.value(), KEY_DISCOVERY_VERSION)?;
            } else if entry.key.eq_ignore_ascii_case(KEY_PROTOCOL_MIN) {
                set_once(&mut protocol_min, entry.value(), KEY_PROTOCOL_MIN)?;
            } else if entry.key.eq_ignore_ascii_case(KEY_PROTOCOL_MAX) {
                set_once(&mut protocol_max, entry.value(), KEY_PROTOCOL_MAX)?;
            } else if entry.key.eq_ignore_ascii_case(KEY_NAME) {
                set_once(&mut name, entry.value(), KEY_NAME)?;
            } else if entry.key.eq_ignore_ascii_case(KEY_PLATFORM) {
                set_once(&mut platform, entry.value(), KEY_PLATFORM)?;
            }
        }

        let version = parse_required_decimal(
            discovery_version.ok_or(DiscoveryMetadataError::MissingField(KEY_DISCOVERY_VERSION))?,
            KEY_DISCOVERY_VERSION,
        )?;
        if version != DISCOVERY_SCHEMA_VERSION {
            return Err(DiscoveryMetadataError::UnsupportedSchemaVersion { version });
        }
        let min = parse_required_decimal(
            protocol_min.ok_or(DiscoveryMetadataError::MissingField(KEY_PROTOCOL_MIN))?,
            KEY_PROTOCOL_MIN,
        )?;
        let max = parse_required_decimal(
            protocol_max.ok_or(DiscoveryMetadataError::MissingField(KEY_PROTOCOL_MAX))?,
            KEY_PROTOCOL_MAX,
        )?;
        let protocols = DiscoveryProtocolRange::new(min, max)
            .map_err(DiscoveryMetadataError::InvalidProtocolRange)?;

        let name = name.and_then(parse_optional_name);
        let platform = platform.and_then(DiscoveryPlatformHint::parse);
        Ok(Self::new(protocols, name, platform))
    }
}

fn set_once<'a>(
    slot: &mut Option<&'a [u8]>,
    value: &'a [u8],
    key: &'static str,
) -> Result<(), DiscoveryMetadataError> {
    if slot.replace(value).is_some() {
        return Err(DiscoveryMetadataError::DuplicateKnownKey(key));
    }
    Ok(())
}

fn parse_required_decimal(value: &[u8], key: &'static str) -> Result<u16, DiscoveryMetadataError> {
    let text = str::from_utf8(value).map_err(|_| DiscoveryMetadataError::MalformedField(key))?;
    let parsed = text
        .parse::<u16>()
        .map_err(|_| DiscoveryMetadataError::MalformedField(key))?;
    if parsed.to_string() != text {
        return Err(DiscoveryMetadataError::MalformedField(key));
    }
    Ok(parsed)
}

fn parse_optional_name(value: &[u8]) -> Option<DiscoveryNameHint> {
    str::from_utf8(value)
        .ok()
        .and_then(|value| DiscoveryNameHint::new(value).ok())
}

/// A bounded discovery TXT record is malformed or unsupported.
#[derive(Debug, Eq, PartialEq)]
pub enum DiscoveryMetadataError {
    /// A TXT key is empty or outside printable ASCII key syntax.
    InvalidTxtKey,
    /// One TXT entry exceeds the DNS-SD length-octet capacity.
    TxtEntryTooLarge { size: usize, maximum: usize },
    /// The complete local-transfer TXT record exceeds its strict budget.
    TotalMetadataTooLarge { size: usize, maximum: usize },
    /// A required known field is absent.
    MissingField(&'static str),
    /// A known key occurs more than once, compared case-insensitively.
    DuplicateKnownKey(&'static str),
    /// A required field is not a canonical unsigned decimal value.
    MalformedField(&'static str),
    /// The discovery schema is well-formed but unsupported.
    UnsupportedSchemaVersion { version: u16 },
    /// The advertised application-protocol range is reversed.
    InvalidProtocolRange(DiscoveryProtocolRangeError),
}

impl fmt::Display for DiscoveryMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTxtKey => formatter.write_str("invalid DNS-SD TXT key"),
            Self::TxtEntryTooLarge { size, maximum } => write!(
                formatter,
                "DNS-SD TXT entry is {size} bytes; maximum is {maximum}"
            ),
            Self::TotalMetadataTooLarge { size, maximum } => write!(
                formatter,
                "local-transfer TXT metadata is {size} bytes; maximum is {maximum}"
            ),
            Self::MissingField(key) => write!(formatter, "missing discovery TXT field `{key}`"),
            Self::DuplicateKnownKey(key) => {
                write!(formatter, "duplicate discovery TXT field `{key}`")
            }
            Self::MalformedField(key) => {
                write!(formatter, "malformed discovery TXT field `{key}`")
            }
            Self::UnsupportedSchemaVersion { version } => {
                write!(formatter, "unsupported discovery schema version {version}")
            }
            Self::InvalidProtocolRange(source) => source.fmt(formatter),
        }
    }
}

impl Error for DiscoveryMetadataError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidProtocolRange(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DISCOVERY_SCHEMA_VERSION, DISCOVERY_SERVICE_TYPE, DiscoveryMetadata,
        DiscoveryMetadataError, DiscoveryNameHint, DiscoveryPlatformHint, DiscoveryProtocolRange,
        DiscoveryTxtEntry, MAX_DISCOVERY_NAME_BYTES, MAX_DISCOVERY_TXT_BYTES,
        MAX_DISCOVERY_TXT_ENTRY_BYTES,
    };
    use crate::device_name::DeviceName;
    use crate::platform::Platform;

    fn entry(key: &str, value: impl AsRef<[u8]>) -> DiscoveryTxtEntry {
        DiscoveryTxtEntry::new(key, value).unwrap()
    }

    fn required_entries() -> Vec<DiscoveryTxtEntry> {
        vec![entry("dv", "1"), entry("pmin", "1"), entry("pmax", "1")]
    }

    #[test]
    fn schema_version_one_and_canonical_service_type_are_explicit() {
        let metadata = DiscoveryMetadata::new(DiscoveryProtocolRange::initial(), None, None);

        assert_eq!(DISCOVERY_SERVICE_TYPE, "_local-transfer._tcp");
        assert_eq!(metadata.schema_version(), DISCOVERY_SCHEMA_VERSION);
        assert_eq!(metadata.schema_version(), 1);
    }

    #[test]
    fn valid_protocol_range_exposes_inclusive_bounds() {
        let range = DiscoveryProtocolRange::new(1, 3).unwrap();

        assert_eq!(range.min(), 1);
        assert_eq!(range.max(), 3);
    }

    #[test]
    fn overlapping_ranges_select_the_highest_common_major() {
        let local = DiscoveryProtocolRange::new(1, 2).unwrap();
        let remote = DiscoveryProtocolRange::new(2, 3).unwrap();

        assert!(local.is_compatible_with(remote));
        assert_eq!(local.highest_compatible_version(remote), Some(2));
    }

    #[test]
    fn non_overlapping_ranges_are_incompatible() {
        let local = DiscoveryProtocolRange::new(1, 1).unwrap();
        let remote = DiscoveryProtocolRange::new(2, 2).unwrap();

        assert!(!local.is_compatible_with(remote));
        assert_eq!(local.highest_compatible_version(remote), None);
    }

    #[test]
    fn reversed_protocol_range_is_a_typed_error() {
        let error = DiscoveryProtocolRange::new(3, 2).unwrap_err();

        assert_eq!(error.min(), 3);
        assert_eq!(error.max(), 2);
    }

    #[test]
    fn every_required_field_is_enforced() {
        for missing in ["dv", "pmin", "pmax"] {
            let entries: Vec<_> = required_entries()
                .into_iter()
                .filter(|entry| entry.key() != missing)
                .collect();

            assert_eq!(
                DiscoveryMetadata::from_txt_entries(&entries).unwrap_err(),
                DiscoveryMetadataError::MissingField(missing)
            );
        }
    }

    #[test]
    fn malformed_required_values_and_reversed_remote_range_are_rejected() {
        for (key, value) in [("dv", "01"), ("pmin", "one"), ("pmax", "")] {
            let mut entries = required_entries();
            entries.retain(|entry| entry.key() != key);
            entries.push(entry(key, value));
            assert_eq!(
                DiscoveryMetadata::from_txt_entries(&entries).unwrap_err(),
                DiscoveryMetadataError::MalformedField(key)
            );
        }

        let reversed = vec![entry("dv", "1"), entry("pmin", "3"), entry("pmax", "2")];
        assert!(matches!(
            DiscoveryMetadata::from_txt_entries(&reversed),
            Err(DiscoveryMetadataError::InvalidProtocolRange(_))
        ));
    }

    #[test]
    fn unsupported_discovery_schema_is_explicit() {
        let entries = vec![entry("dv", "2"), entry("pmin", "1"), entry("pmax", "1")];

        assert_eq!(
            DiscoveryMetadata::from_txt_entries(&entries).unwrap_err(),
            DiscoveryMetadataError::UnsupportedSchemaVersion { version: 2 }
        );
    }

    #[test]
    fn duplicate_known_keys_are_rejected_case_insensitively() {
        let mut entries = required_entries();
        entries.push(entry("DV", "1"));

        assert_eq!(
            DiscoveryMetadata::from_txt_entries(&entries).unwrap_err(),
            DiscoveryMetadataError::DuplicateKnownKey("dv")
        );
    }

    #[test]
    fn unknown_keys_are_ignored_within_the_safety_budget() {
        let mut entries = required_entries();
        entries.push(entry("future", b"extension"));

        let metadata = DiscoveryMetadata::from_txt_entries(&entries).unwrap();

        assert_eq!(metadata.protocols(), DiscoveryProtocolRange::initial());
        assert!(metadata.name().is_none());
        assert!(metadata.platform().is_none());
    }

    #[test]
    fn individual_and_total_txt_size_limits_are_enforced() {
        let value = vec![b'x'; MAX_DISCOVERY_TXT_ENTRY_BYTES];
        assert!(matches!(
            DiscoveryTxtEntry::new("x", value),
            Err(DiscoveryMetadataError::TxtEntryTooLarge { .. })
        ));

        let mut entries = required_entries();
        entries.push(entry("future-a", vec![b'a'; 246]));
        entries.push(entry("future-b", vec![b'b'; 246]));
        let error = DiscoveryMetadata::from_txt_entries(&entries).unwrap_err();
        assert!(matches!(
            error,
            DiscoveryMetadataError::TotalMetadataTooLarge {
                size,
                maximum: MAX_DISCOVERY_TXT_BYTES
            } if size > MAX_DISCOVERY_TXT_BYTES
        ));
    }

    #[test]
    fn name_hint_enforces_its_utf8_byte_limit() {
        let exact = "界".repeat(MAX_DISCOVERY_NAME_BYTES / 3);
        let too_long = format!("{exact}a");

        assert_eq!(DiscoveryNameHint::new(exact).unwrap().as_str().len(), 96);
        assert!(DiscoveryNameHint::new(too_long).is_err());
    }

    #[test]
    fn device_name_hint_truncation_is_unicode_safe_and_non_mutating() {
        let persisted = DeviceName::new("界".repeat(64)).unwrap();
        let original = persisted.as_str().to_owned();

        let hint = DiscoveryNameHint::from_device_name(&persisted);

        assert_eq!(hint.as_str(), "界".repeat(32));
        assert_eq!(hint.as_str().len(), MAX_DISCOVERY_NAME_BYTES);
        assert_eq!(persisted.as_str(), original);
    }

    #[test]
    fn all_bounded_optional_hints_round_trip() {
        for (platform, expected) in [
            (Platform::MacOs, DiscoveryPlatformHint::MacOs),
            (Platform::Windows, DiscoveryPlatformHint::Windows),
            (Platform::Linux, DiscoveryPlatformHint::Linux),
        ] {
            let metadata = DiscoveryMetadata::new(
                DiscoveryProtocolRange::initial(),
                Some(DiscoveryNameHint::new("Studio Workstation").unwrap()),
                Some(platform.into()),
            );
            let parsed = DiscoveryMetadata::from_txt_entries(&metadata.to_txt_entries()).unwrap();

            assert_eq!(parsed.name().unwrap().as_str(), "Studio Workstation");
            assert_eq!(parsed.platform(), Some(expected));
        }
    }

    #[test]
    fn malformed_optional_hints_are_discarded_without_hiding_a_valid_peer() {
        let mut entries = required_entries();
        entries.push(entry("name", [0xff]));
        entries.push(entry("os", "freebsd"));

        let metadata = DiscoveryMetadata::from_txt_entries(&entries).unwrap();

        assert_eq!(metadata.protocols(), DiscoveryProtocolRange::initial());
        assert!(metadata.name().is_none());
        assert!(metadata.platform().is_none());
    }

    #[test]
    fn local_encoder_emits_only_documented_privacy_bounded_keys() {
        let metadata = DiscoveryMetadata::new(
            DiscoveryProtocolRange::initial(),
            Some(DiscoveryNameHint::new("Living Room").unwrap()),
            Some(DiscoveryPlatformHint::Linux),
        );

        let entries = metadata.to_txt_entries();
        let keys: Vec<_> = entries.iter().map(DiscoveryTxtEntry::key).collect();
        let total: usize = entries.iter().map(DiscoveryTxtEntry::encoded_size).sum();

        assert_eq!(keys, ["dv", "pmin", "pmax", "name", "os"]);
        assert!(total <= MAX_DISCOVERY_TXT_BYTES);
    }
}
