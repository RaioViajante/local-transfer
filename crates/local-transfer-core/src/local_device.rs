//! Public boundary for the current local device.

use std::error::Error;
use std::fmt;
use std::path::Path;

use directories::ProjectDirs;

use crate::device_name::DeviceNameStore;
use crate::device_name::{DeviceName, DeviceNameError};
use crate::identity::{DeviceId, DeviceIdError, DeviceIdStore};
use crate::platform::{Platform, UnsupportedPlatformError};

/// An immutable snapshot of the current local device state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDevice {
    id: DeviceId,
    name: DeviceName,
    platform: Platform,
}

impl LocalDevice {
    /// Returns the permanent opaque installation identifier.
    #[must_use]
    pub const fn id(&self) -> DeviceId {
        self.id
    }

    /// Returns the mutable user-facing display name in this snapshot.
    #[must_use]
    pub fn name(&self) -> &DeviceName {
        &self.name
    }

    /// Returns the bounded operating-system family.
    #[must_use]
    pub const fn platform(&self) -> Platform {
        self.platform
    }
}

/// Coordinates local-device operations without exposing persistence mechanics.
#[derive(Clone, Debug)]
pub struct LocalDeviceManager {
    id_store: DeviceIdStore,
    name_store: DeviceNameStore,
    platform: PlatformSource,
}

impl LocalDeviceManager {
    /// Uses the current user's established `local-transfer` configuration directory.
    pub fn for_current_user() -> Result<Self, LocalDeviceError> {
        let project_dirs = ProjectDirs::from("", "", "local-transfer")
            .ok_or(LocalDeviceError::ConfigDirectoryUnavailable)?;
        Ok(Self::in_app_config(project_dirs.config_dir()))
    }

    /// Loads a snapshot, creating missing ID and name state with existing semantics.
    ///
    /// Platform detection happens first so an unsupported target cannot create
    /// filesystem state. The permanent ID is then loaded before the mutable name,
    /// so a corrupt identity never creates or resets display-name state.
    pub fn load(&self) -> Result<LocalDevice, LocalDeviceError> {
        let platform = self.platform.detect()?;
        let id = self.id_store.load_or_create()?;
        let name = self.name_store.load_or_create()?;
        Ok(LocalDevice { id, name, platform })
    }

    /// Validates and atomically persists a new display name.
    ///
    /// This operation touches only display-name storage and returns the normalized
    /// domain value. It never reads, rewrites, or regenerates the device ID.
    pub fn update_name(&self, value: impl AsRef<str>) -> Result<DeviceName, LocalDeviceError> {
        self.name_store.update(value).map_err(Into::into)
    }

    fn in_app_config(directory: &Path) -> Self {
        Self {
            id_store: DeviceIdStore::in_app_config(directory),
            name_store: DeviceNameStore::in_app_config(directory),
            platform: PlatformSource::Current,
        }
    }

    #[cfg(test)]
    fn for_test(directory: &Path) -> Self {
        Self {
            id_store: DeviceIdStore::new(directory.join("device-id")),
            name_store: DeviceNameStore::new(directory.join("device-name")),
            platform: PlatformSource::Current,
        }
    }
}

#[derive(Clone, Debug)]
enum PlatformSource {
    Current,
    #[cfg(test)]
    Target(String),
}

impl PlatformSource {
    fn detect(&self) -> Result<Platform, UnsupportedPlatformError> {
        match self {
            Self::Current => Platform::current(),
            #[cfg(test)]
            Self::Target(target) => Platform::from_target_os(target),
        }
    }
}

/// Failures while locating, loading, or updating the current local device.
#[derive(Debug)]
pub enum LocalDeviceError {
    /// The operating system did not provide an application configuration directory.
    ConfigDirectoryUnavailable,
    /// Loading or creating the permanent device ID failed.
    DeviceId(DeviceIdError),
    /// Loading, creating, validating, or updating the display name failed.
    DeviceName(DeviceNameError),
    /// The compilation target is not a supported platform.
    Platform(UnsupportedPlatformError),
}

impl fmt::Display for LocalDeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirectoryUnavailable => {
                formatter.write_str("the local configuration directory is unavailable")
            }
            Self::DeviceId(source) => write!(formatter, "local device ID error: {source}"),
            Self::DeviceName(source) => write!(formatter, "local device name error: {source}"),
            Self::Platform(source) => write!(formatter, "local device platform error: {source}"),
        }
    }
}

impl Error for LocalDeviceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DeviceId(source) => Some(source),
            Self::DeviceName(source) => Some(source),
            Self::Platform(source) => Some(source),
            Self::ConfigDirectoryUnavailable => None,
        }
    }
}

impl From<DeviceIdError> for LocalDeviceError {
    fn from(source: DeviceIdError) -> Self {
        Self::DeviceId(source)
    }
}

impl From<DeviceNameError> for LocalDeviceError {
    fn from(source: DeviceNameError) -> Self {
        Self::DeviceName(source)
    }
}

impl From<UnsupportedPlatformError> for LocalDeviceError {
    fn from(source: UnsupportedPlatformError) -> Self {
        Self::Platform(source)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{LocalDeviceError, LocalDeviceManager, PlatformSource};
    use crate::device_name::{DEFAULT_DEVICE_NAME, DeviceNameError, DeviceNameValidationError};
    use crate::identity::DeviceIdError;
    use crate::platform::Platform;

    #[test]
    fn first_load_creates_and_returns_a_complete_device() {
        let directory = tempdir().unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());

        let device = manager.load().unwrap();

        assert_eq!(device.name().as_str(), DEFAULT_DEVICE_NAME);
        assert_eq!(device.platform(), Platform::current().unwrap());
        assert_eq!(
            fs::read_to_string(directory.path().join("device-id")).unwrap(),
            format!("{}\n", device.id())
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("device-name")).unwrap(),
            "Local Device\n"
        );
    }

    #[test]
    fn repeated_loads_preserve_the_device_id_and_persisted_name() {
        let directory = tempdir().unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());
        let first = manager.load().unwrap();
        manager.update_name("Studio Workstation").unwrap();

        let second = manager.load().unwrap();

        assert_eq!(second.id(), first.id());
        assert_eq!(second.name().as_str(), "Studio Workstation");
    }

    #[test]
    fn isolated_installations_have_distinct_ids_and_the_same_neutral_default_name() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first = LocalDeviceManager::for_test(first_directory.path())
            .load()
            .unwrap();
        let second = LocalDeviceManager::for_test(second_directory.path())
            .load()
            .unwrap();

        assert_ne!(first.id(), second.id());
        assert_eq!(first.name(), second.name());
        assert_eq!(first.name().as_str(), DEFAULT_DEVICE_NAME);
    }

    #[test]
    fn updating_name_is_visible_on_reload_and_leaves_id_bytes_unchanged() {
        let directory = tempdir().unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());
        manager.load().unwrap();
        let id_path = directory.path().join("device-id");
        let id_before = fs::read(&id_path).unwrap();

        let updated = manager.update_name("  Sala de José 🛰️  ").unwrap();

        assert_eq!(updated.as_str(), "Sala de José 🛰️");
        assert_eq!(manager.load().unwrap().name(), &updated);
        assert_eq!(fs::read(id_path).unwrap(), id_before);
    }

    #[test]
    fn name_validation_error_preserves_its_typed_cause() {
        let directory = tempdir().unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());

        let error = manager.update_name("bad\nname").unwrap_err();

        assert!(matches!(
            error,
            LocalDeviceError::DeviceName(DeviceNameError::Validation(
                DeviceNameValidationError::ControlCharacter
            ))
        ));
        assert!(!directory.path().join("device-id").exists());
    }

    #[test]
    fn invalid_name_update_preserves_the_previous_public_snapshot() {
        let directory = tempdir().unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());
        manager.load().unwrap();
        manager.update_name("Studio Workstation").unwrap();
        let before = manager.load().unwrap();

        let error = manager.update_name("bad\nname").unwrap_err();
        let after = manager.load().unwrap();

        assert!(matches!(
            error,
            LocalDeviceError::DeviceName(DeviceNameError::Validation(
                DeviceNameValidationError::ControlCharacter
            ))
        ));
        assert_eq!(after, before);
    }

    #[test]
    fn corrupt_id_propagates_without_creating_name_state() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join("device-id"), "corrupt\n").unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());

        let error = manager.load().unwrap_err();

        assert!(matches!(
            error,
            LocalDeviceError::DeviceId(DeviceIdError::Invalid { .. })
        ));
        assert!(!directory.path().join("device-name").exists());
    }

    #[test]
    fn corrupt_name_propagates_without_replacing_it_or_the_id() {
        let directory = tempdir().unwrap();
        let manager = LocalDeviceManager::for_test(directory.path());
        let original = manager.load().unwrap();
        let id_before = fs::read(directory.path().join("device-id")).unwrap();
        fs::write(directory.path().join("device-name"), "\n").unwrap();

        let error = manager.load().unwrap_err();

        assert!(matches!(
            error,
            LocalDeviceError::DeviceName(DeviceNameError::Invalid { .. })
        ));
        assert_eq!(
            fs::read(directory.path().join("device-id")).unwrap(),
            id_before
        );
        assert_eq!(manager.id_store.load_or_create().unwrap(), original.id());
        assert_eq!(
            fs::read_to_string(directory.path().join("device-name")).unwrap(),
            "\n"
        );
    }

    #[test]
    fn unsupported_platform_is_testable_and_creates_no_state() {
        let directory = tempdir().unwrap();
        let mut manager = LocalDeviceManager::for_test(directory.path());
        manager.platform = PlatformSource::Target("freebsd".to_owned());

        let error = manager.load().unwrap_err();

        assert!(matches!(error, LocalDeviceError::Platform(_)));
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }

    #[test]
    fn public_operations_have_storage_free_signatures() {
        let _: fn() -> Result<LocalDeviceManager, LocalDeviceError> =
            LocalDeviceManager::for_current_user;
        fn assert_load_signature(
            manager: &LocalDeviceManager,
        ) -> Result<super::LocalDevice, LocalDeviceError> {
            manager.load()
        }
        let _ = assert_load_signature;
    }
}
