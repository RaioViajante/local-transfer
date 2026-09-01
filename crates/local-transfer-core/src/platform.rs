//! Bounded local operating-system metadata.

use std::error::Error;
use std::fmt;

/// A supported operating-system family.
///
/// Platform is descriptive metadata only. It is not a device identifier,
/// uniqueness mechanism, trust anchor, or cryptographic identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Platform {
    /// Apple macOS.
    MacOs,
    /// Microsoft Windows.
    Windows,
    /// Linux.
    Linux,
}

impl Platform {
    /// Detects the operating-system family selected by the Rust compilation target.
    ///
    /// This reads only Rust's compile-target constant and performs no host,
    /// hardware, user, filesystem, process, or network inspection.
    pub fn current() -> Result<Self, UnsupportedPlatformError> {
        Self::from_target_os(std::env::consts::OS)
    }

    /// Returns the stable internal textual representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    fn from_target_os(target_os: &str) -> Result<Self, UnsupportedPlatformError> {
        match target_os {
            "macos" => Ok(Self::MacOs),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            unsupported => Err(UnsupportedPlatformError {
                target_os: unsupported.to_owned(),
            }),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The Rust compilation target is not one of the supported OS families.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedPlatformError {
    target_os: String,
}

impl UnsupportedPlatformError {
    /// Returns Rust's unsupported target OS value.
    #[must_use]
    pub fn target_os(&self) -> &str {
        &self.target_os
    }
}

impl fmt::Display for UnsupportedPlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported operating-system target: {}",
            self.target_os
        )
    }
}

impl Error for UnsupportedPlatformError {}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{Platform, UnsupportedPlatformError};
    use crate::device_name::DeviceNameStore;
    use crate::identity::DeviceIdStore;

    #[test]
    fn supported_target_values_map_to_bounded_platforms() {
        assert_eq!(Platform::from_target_os("macos"), Ok(Platform::MacOs));
        assert_eq!(Platform::from_target_os("windows"), Ok(Platform::Windows));
        assert_eq!(Platform::from_target_os("linux"), Ok(Platform::Linux));
    }

    #[test]
    fn supported_platforms_have_stable_internal_representations() {
        assert_eq!(Platform::MacOs.as_str(), "macos");
        assert_eq!(Platform::Windows.as_str(), "windows");
        assert_eq!(Platform::Linux.as_str(), "linux");
    }

    #[test]
    fn unsupported_target_is_an_explicit_error() {
        let error = Platform::from_target_os("freebsd").unwrap_err();

        assert_eq!(
            error,
            UnsupportedPlatformError {
                target_os: "freebsd".to_owned(),
            }
        );
        assert_eq!(error.target_os(), "freebsd");
    }

    #[test]
    fn current_platform_matches_the_rust_compilation_target() {
        let detected = Platform::current();

        #[cfg(target_os = "macos")]
        assert_eq!(detected, Ok(Platform::MacOs));
        #[cfg(target_os = "windows")]
        assert_eq!(detected, Ok(Platform::Windows));
        #[cfg(target_os = "linux")]
        assert_eq!(detected, Ok(Platform::Linux));
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        assert_eq!(detected.unwrap_err().target_os(), std::env::consts::OS);
    }

    #[test]
    fn detection_does_not_modify_device_id_or_device_name() {
        let directory = tempdir().unwrap();
        let id_path = directory.path().join("device-id");
        let name_path = directory.path().join("device-name");
        DeviceIdStore::new(&id_path).load_or_create().unwrap();
        DeviceNameStore::new(&name_path).load_or_create().unwrap();
        let id_before = fs::read(&id_path).unwrap();
        let name_before = fs::read(&name_path).unwrap();

        let _ = Platform::current();

        assert_eq!(fs::read(id_path).unwrap(), id_before);
        assert_eq!(fs::read(name_path).unwrap(), name_before);
    }
}
