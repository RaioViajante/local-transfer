//! Mutable local device display name.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;

use tempfile::NamedTempFile;

use crate::persistence::{
    PersistenceError, PersistenceOperation, create_synced_temporary, harden_existing_file,
    harden_existing_parent,
};

/// The neutral display name used until the user chooses another one.
pub const DEFAULT_DEVICE_NAME: &str = "Local Device";

/// The maximum number of Unicode scalar values allowed in a display name.
pub const MAX_DEVICE_NAME_CHARS: usize = 64;

const DEVICE_NAME_FILE_NAME: &str = "device-name";

/// A validated, user-facing label for the local device.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DeviceName(String);

impl DeviceName {
    /// Validates and normalizes a display name.
    ///
    /// Control characters are rejected before surrounding Unicode whitespace
    /// is trimmed. The normalized name must contain 1 to 64 Unicode scalar
    /// values. Interior spaces and Unicode text are allowed.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DeviceNameValidationError> {
        let value = value.as_ref();
        if value.chars().any(char::is_control) {
            return Err(DeviceNameValidationError::ControlCharacter);
        }

        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(DeviceNameValidationError::Empty);
        }
        if normalized.chars().count() > MAX_DEVICE_NAME_CHARS {
            return Err(DeviceNameValidationError::TooLong {
                maximum: MAX_DEVICE_NAME_CHARS,
            });
        }

        Ok(Self(normalized.to_owned()))
    }

    /// Returns the normalized display name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for DeviceName {
    fn default() -> Self {
        Self(DEFAULT_DEVICE_NAME.to_owned())
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A display-name validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceNameValidationError {
    /// The normalized display name is empty.
    Empty,
    /// The normalized display name exceeds the supported length.
    TooLong { maximum: usize },
    /// The input contains a control character.
    ControlCharacter,
}

impl fmt::Display for DeviceNameValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("device display name must not be empty"),
            Self::TooLong { maximum } => {
                write!(
                    formatter,
                    "device display name must not exceed {maximum} Unicode characters"
                )
            }
            Self::ControlCharacter => {
                formatter.write_str("device display name must not contain control characters")
            }
        }
    }
}

impl Error for DeviceNameValidationError {}

/// A filesystem-backed store for the mutable local device display name.
#[derive(Clone, Debug)]
pub(crate) struct DeviceNameStore {
    path: PathBuf,
    harden_existing_parent: bool,
}

impl DeviceNameStore {
    /// Creates a store at an explicit path.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            harden_existing_parent: false,
        }
    }

    /// Creates a store in the platform's application configuration directory.
    pub(crate) fn in_app_config(directory: impl Into<PathBuf>) -> Self {
        Self {
            path: directory.into().join(DEVICE_NAME_FILE_NAME),
            harden_existing_parent: true,
        }
    }

    /// Loads the persisted name or creates the neutral default when it is absent.
    ///
    /// Existing unreadable or invalid data is returned as an error and is never
    /// silently replaced with the default.
    pub(crate) fn load_or_create(&self) -> Result<DeviceName, DeviceNameError> {
        if self.harden_existing_parent {
            harden_existing_parent(&self.path).map_err(Self::persistence_error)?;
        }
        harden_existing_file(&self.path).map_err(Self::persistence_error)?;
        match fs::read_to_string(&self.path) {
            Ok(contents) => self.parse_persisted(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.create_default(),
            Err(source) => Err(self.io_error("read device display name", source)),
        }
    }

    /// Validates and atomically persists a new display name.
    ///
    /// Concurrent successful updates use last-writer-wins semantics. Readers see
    /// either the complete previous value or the complete new value.
    pub(crate) fn update(&self, value: impl AsRef<str>) -> Result<DeviceName, DeviceNameError> {
        let name = DeviceName::new(value).map_err(DeviceNameError::Validation)?;
        let temporary = self.write_temporary(&name)?;
        let file = temporary
            .persist(&self.path)
            .map_err(|error| self.io_error("persist device display name", error.error))?;
        file.sync_all()
            .map_err(|source| self.io_error("sync device display name", source))?;
        Ok(name)
    }

    fn parse_persisted(&self, contents: &str) -> Result<DeviceName, DeviceNameError> {
        let value = contents.strip_suffix('\n').unwrap_or(contents);
        DeviceName::new(value).map_err(|source| DeviceNameError::Invalid {
            path: self.path.clone(),
            source,
        })
    }

    fn create_default(&self) -> Result<DeviceName, DeviceNameError> {
        let name = DeviceName::default();
        let temporary = self.write_temporary(&name)?;

        match temporary.persist_noclobber(&self.path) {
            Ok(file) => {
                file.sync_all()
                    .map_err(|source| self.io_error("sync device display name", source))?;
                Ok(name)
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.load_existing_after_race()
            }
            Err(error) => Err(self.io_error("persist device display name", error.error)),
        }
    }

    fn write_temporary(&self, name: &DeviceName) -> Result<NamedTempFile, DeviceNameError> {
        create_synced_temporary(
            &self.path,
            format!("{name}\n").as_bytes(),
            self.harden_existing_parent,
        )
        .map_err(Self::persistence_error)
    }

    fn load_existing_after_race(&self) -> Result<DeviceName, DeviceNameError> {
        harden_existing_file(&self.path).map_err(Self::persistence_error)?;
        let contents = fs::read_to_string(&self.path).map_err(|source| {
            self.io_error("read concurrently created device display name", source)
        })?;
        self.parse_persisted(&contents)
    }

    fn io_error(&self, operation: &'static str, source: std::io::Error) -> DeviceNameError {
        DeviceNameError::Io {
            operation,
            path: self.path.clone(),
            source,
        }
    }

    fn persistence_error(error: PersistenceError) -> DeviceNameError {
        match error {
            PersistenceError::InvalidPath { path } => DeviceNameError::InvalidPath { path },
            PersistenceError::Io {
                operation,
                path,
                source,
            } => DeviceNameError::Io {
                operation: match operation {
                    PersistenceOperation::InspectDirectory => {
                        "inspect device display name directory"
                    }
                    PersistenceOperation::CreateDirectory => "create device display name directory",
                    PersistenceOperation::HardenDirectory => {
                        "harden device display name directory permissions"
                    }
                    PersistenceOperation::HardenFile => {
                        "harden device display name file permissions"
                    }
                    PersistenceOperation::CreateTemporary => "create temporary device display name",
                    PersistenceOperation::WriteTemporary => "write temporary device display name",
                    PersistenceOperation::SyncTemporary => "sync temporary device display name",
                },
                path,
                source,
            },
        }
    }
}

/// Failures while locating, validating, reading, or writing a display name.
#[derive(Debug)]
pub enum DeviceNameError {
    /// The operating system did not provide an application configuration directory.
    ConfigDirectoryUnavailable,
    /// The configured name path has no parent directory.
    InvalidPath { path: PathBuf },
    /// A proposed display name is invalid.
    Validation(DeviceNameValidationError),
    /// Persisted content is not a valid display name.
    Invalid {
        path: PathBuf,
        source: DeviceNameValidationError,
    },
    /// A filesystem operation failed.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for DeviceNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirectoryUnavailable => {
                formatter.write_str("the local configuration directory is unavailable")
            }
            Self::InvalidPath { path } => write!(
                formatter,
                "device display name path has no parent: {}",
                path.display()
            ),
            Self::Validation(source) => source.fmt(formatter),
            Self::Invalid { path, .. } => write!(
                formatter,
                "invalid persisted device display name at {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} at {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for DeviceNameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validation(source) | Self::Invalid { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::ConfigDirectoryUnavailable | Self::InvalidPath { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        DEFAULT_DEVICE_NAME, DeviceName, DeviceNameError, DeviceNameStore,
        DeviceNameValidationError, MAX_DEVICE_NAME_CHARS,
    };
    use crate::identity::DeviceIdStore;

    #[test]
    fn first_load_establishes_and_persists_the_neutral_default() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/device-name");
        let store = DeviceNameStore::new(&path);

        let name = store.load_or_create().unwrap();

        assert_eq!(name.as_str(), DEFAULT_DEVICE_NAME);
        assert_eq!(fs::read_to_string(path).unwrap(), "Local Device\n");
        assert_eq!(store.load_or_create().unwrap(), name);
    }

    #[test]
    fn editing_persists_and_reload_returns_the_new_name() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-name");
        let store = DeviceNameStore::new(&path);
        store.load_or_create().unwrap();

        let edited = store.update("Studio Workstation").unwrap();

        assert_eq!(edited.as_str(), "Studio Workstation");
        assert_eq!(fs::read_to_string(path).unwrap(), "Studio Workstation\n");
        assert_eq!(store.load_or_create().unwrap(), edited);
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_before_persistence() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-name");
        let store = DeviceNameStore::new(&path);

        let name = store.update("  Living Room Device  ").unwrap();

        assert_eq!(name.as_str(), "Living Room Device");
        assert_eq!(fs::read_to_string(path).unwrap(), "Living Room Device\n");
    }

    #[test]
    fn empty_and_whitespace_only_names_are_rejected() {
        assert_eq!(
            DeviceName::new("").unwrap_err(),
            DeviceNameValidationError::Empty
        );
        assert_eq!(
            DeviceName::new("   ").unwrap_err(),
            DeviceNameValidationError::Empty
        );
    }

    #[test]
    fn names_longer_than_the_character_limit_are_rejected() {
        let too_long = "界".repeat(MAX_DEVICE_NAME_CHARS + 1);

        assert_eq!(
            DeviceName::new(too_long).unwrap_err(),
            DeviceNameValidationError::TooLong {
                maximum: MAX_DEVICE_NAME_CHARS,
            }
        );
    }

    #[test]
    fn control_characters_are_rejected_even_at_the_edges() {
        for value in ["Line\nBreak", "Tabbed\tName", "Trailing\n"] {
            assert_eq!(
                DeviceName::new(value).unwrap_err(),
                DeviceNameValidationError::ControlCharacter
            );
        }
    }

    #[test]
    fn valid_unicode_and_interior_spaces_are_accepted() {
        let name = DeviceName::new("  Sala de José 🛰️  ").unwrap();

        assert_eq!(name.as_str(), "Sala de José 🛰️");
    }

    #[test]
    fn corrupt_persisted_name_is_an_error_and_is_not_replaced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-name");
        fs::write(&path, "\n").unwrap();

        let error = DeviceNameStore::new(&path).load_or_create().unwrap_err();

        assert!(matches!(error, DeviceNameError::Invalid { .. }));
        assert_eq!(fs::read_to_string(path).unwrap(), "\n");
    }

    #[test]
    fn update_validation_failure_leaves_the_persisted_name_unchanged() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-name");
        let store = DeviceNameStore::new(&path);
        let original = store.load_or_create().unwrap();

        let error = store.update("bad\nname").unwrap_err();

        assert!(matches!(error, DeviceNameError::Validation(_)));
        assert_eq!(store.load_or_create().unwrap(), original);
    }

    #[test]
    fn changing_deleting_or_corrupting_the_name_leaves_the_device_id_unchanged() {
        let directory = tempdir().unwrap();
        let id_path = directory.path().join("device-id");
        let name_path = directory.path().join("device-name");
        let id_store = DeviceIdStore::new(&id_path);
        let name_store = DeviceNameStore::new(&name_path);
        let original_id = id_store.load_or_create().unwrap();
        let original_id_contents = fs::read(&id_path).unwrap();

        name_store.load_or_create().unwrap();
        name_store.update("Renamed Device").unwrap();
        assert_eq!(id_store.load_or_create().unwrap(), original_id);
        assert_eq!(fs::read(&id_path).unwrap(), original_id_contents);

        fs::remove_file(&name_path).unwrap();
        assert_eq!(name_store.load_or_create().unwrap(), DeviceName::default());
        assert_eq!(id_store.load_or_create().unwrap(), original_id);
        assert_eq!(fs::read(&id_path).unwrap(), original_id_contents);

        fs::write(name_path, "\n").unwrap();
        assert!(matches!(
            name_store.load_or_create().unwrap_err(),
            DeviceNameError::Invalid { .. }
        ));

        assert_eq!(id_store.load_or_create().unwrap(), original_id);
        assert_eq!(fs::read(id_path).unwrap(), original_id_contents);
    }

    #[test]
    fn filesystem_read_failures_are_explicit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-name");
        fs::create_dir(&path).unwrap();

        let error = DeviceNameStore::new(path).load_or_create().unwrap_err();

        assert!(matches!(error, DeviceNameError::Io { .. }));
    }
}
