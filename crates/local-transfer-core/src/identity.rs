//! Stable local device identity.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use directories::ProjectDirs;
use tempfile::NamedTempFile;
use uuid::Uuid;

const IDENTITY_FILE_NAME: &str = "device-id";

/// An opaque, randomly generated identifier for a local installation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeviceId(Uuid);

impl DeviceId {
    /// Generates a new identifier with randomness supplied by the operating system.
    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl FromStr for DeviceId {
    type Err = ParseDeviceIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(value).map_err(|_| ParseDeviceIdError)?;
        if value != uuid.hyphenated().to_string() || uuid.get_version_num() != 4 {
            return Err(ParseDeviceIdError);
        }
        Ok(Self(uuid))
    }
}

/// An error returned when text is not the canonical representation of a random device ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseDeviceIdError;

impl fmt::Display for ParseDeviceIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a canonical UUID version 4 device ID")
    }
}

impl Error for ParseDeviceIdError {}

/// A filesystem-backed store for the local device identifier.
#[derive(Clone, Debug)]
pub struct DeviceIdStore {
    path: PathBuf,
}

impl DeviceIdStore {
    /// Creates a store at an explicit path.
    ///
    /// Supplying the path keeps persistence isolated and testable.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Creates a store in the platform's application configuration directory.
    pub fn for_current_user() -> Result<Self, DeviceIdError> {
        let project_dirs = ProjectDirs::from("", "", "local-transfer")
            .ok_or(DeviceIdError::ConfigDirectoryUnavailable)?;
        Ok(Self::new(
            project_dirs.config_dir().join(IDENTITY_FILE_NAME),
        ))
    }

    /// Loads the existing ID or creates and persists one when no ID exists.
    ///
    /// Existing unreadable or invalid data is always returned as an error and is
    /// never replaced with a new identity.
    pub fn load_or_create(&self) -> Result<DeviceId, DeviceIdError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => self.parse_persisted(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.create(),
            Err(source) => Err(DeviceIdError::Io {
                operation: "read device identity",
                path: self.path.clone(),
                source,
            }),
        }
    }

    fn parse_persisted(&self, contents: &str) -> Result<DeviceId, DeviceIdError> {
        let value = contents.strip_suffix('\n').unwrap_or(contents);
        value.parse().map_err(|source| DeviceIdError::Invalid {
            path: self.path.clone(),
            source,
        })
    }

    fn create(&self) -> Result<DeviceId, DeviceIdError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DeviceIdError::InvalidPath {
                path: self.path.clone(),
            })?;
        fs::create_dir_all(parent).map_err(|source| DeviceIdError::Io {
            operation: "create device identity directory",
            path: parent.to_path_buf(),
            source,
        })?;

        let device_id = DeviceId::random();
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| DeviceIdError::Io {
            operation: "create temporary device identity",
            path: parent.to_path_buf(),
            source,
        })?;
        writeln!(temporary, "{device_id}").map_err(|source| DeviceIdError::Io {
            operation: "write temporary device identity",
            path: temporary.path().to_path_buf(),
            source,
        })?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|source| DeviceIdError::Io {
                operation: "sync temporary device identity",
                path: temporary.path().to_path_buf(),
                source,
            })?;

        match temporary.persist_noclobber(&self.path) {
            Ok(file) => {
                file.sync_all().map_err(|source| DeviceIdError::Io {
                    operation: "sync device identity",
                    path: self.path.clone(),
                    source,
                })?;
                Ok(device_id)
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.load_existing_after_race()
            }
            Err(error) => Err(DeviceIdError::Io {
                operation: "persist device identity",
                path: self.path.clone(),
                source: error.error,
            }),
        }
    }

    fn load_existing_after_race(&self) -> Result<DeviceId, DeviceIdError> {
        let contents = fs::read_to_string(&self.path).map_err(|source| DeviceIdError::Io {
            operation: "read concurrently created device identity",
            path: self.path.clone(),
            source,
        })?;
        self.parse_persisted(&contents)
    }
}

/// Failures while locating, reading, validating, or creating a device ID.
#[derive(Debug)]
pub enum DeviceIdError {
    /// The operating system did not provide an application configuration directory.
    ConfigDirectoryUnavailable,
    /// The configured identity path has no parent directory.
    InvalidPath { path: PathBuf },
    /// Persisted content is not a canonical UUID version 4 identifier.
    Invalid {
        path: PathBuf,
        source: ParseDeviceIdError,
    },
    /// A filesystem operation failed.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for DeviceIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirectoryUnavailable => {
                formatter.write_str("the local configuration directory is unavailable")
            }
            Self::InvalidPath { path } => {
                write!(
                    formatter,
                    "device identity path has no parent: {}",
                    path.display()
                )
            }
            Self::Invalid { path, .. } => {
                write!(
                    formatter,
                    "invalid persisted device identity at {}",
                    path.display()
                )
            }
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

impl Error for DeviceIdError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::ConfigDirectoryUnavailable | Self::InvalidPath { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tempfile::tempdir;

    use super::{DeviceId, DeviceIdError, DeviceIdStore};

    #[test]
    fn first_initialization_generates_and_persists_a_version_four_uuid() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/device-id");
        let store = DeviceIdStore::new(&path);

        let device_id = store.load_or_create().unwrap();

        assert_eq!(
            device_id.to_string().parse::<DeviceId>().unwrap(),
            device_id
        );
        assert_eq!(fs::read_to_string(path).unwrap(), format!("{device_id}\n"));
    }

    #[test]
    fn loading_again_returns_exactly_the_same_identity() {
        let directory = tempdir().unwrap();
        let store = DeviceIdStore::new(directory.path().join("device-id"));

        let first = store.load_or_create().unwrap();
        let second = store.load_or_create().unwrap();

        assert_eq!(second, first);
    }

    #[test]
    fn independent_storage_locations_receive_different_identities() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();

        let first = DeviceIdStore::new(first_directory.path().join("device-id"))
            .load_or_create()
            .unwrap();
        let second = DeviceIdStore::new(second_directory.path().join("device-id"))
            .load_or_create()
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn concurrent_initialization_keeps_one_persisted_identity() {
        let directory = tempdir().unwrap();
        let store = DeviceIdStore::new(directory.path().join("device-id"));
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.load_or_create().unwrap()
                })
            })
            .collect();
        let identities: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(identities[0], identities[1]);
        assert_eq!(store.load_or_create().unwrap(), identities[0]);
    }

    #[test]
    fn malformed_existing_identity_is_an_error_and_is_not_replaced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-id");
        fs::write(&path, "not-a-device-id\n").unwrap();
        let store = DeviceIdStore::new(&path);

        let error = store.load_or_create().unwrap_err();

        assert!(matches!(error, DeviceIdError::Invalid { .. }));
        assert_eq!(fs::read_to_string(path).unwrap(), "not-a-device-id\n");
    }

    #[test]
    fn non_random_uuid_is_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-id");
        fs::write(&path, "00000000-0000-0000-0000-000000000000\n").unwrap();

        let error = DeviceIdStore::new(path).load_or_create().unwrap_err();

        assert!(matches!(error, DeviceIdError::Invalid { .. }));
    }

    #[test]
    fn filesystem_failures_are_explicit() {
        let directory = tempdir().unwrap();
        let parent_file = directory.path().join("not-a-directory");
        fs::write(&parent_file, "occupied").unwrap();

        let error = DeviceIdStore::new(parent_file.join("device-id"))
            .load_or_create()
            .unwrap_err();

        assert!(matches!(error, DeviceIdError::Io { .. }));
    }

    #[test]
    fn existing_directory_at_identity_path_is_an_explicit_read_error() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("device-id");
        fs::create_dir(&path).unwrap();

        let error = DeviceIdStore::new(path).load_or_create().unwrap_err();

        assert!(matches!(error, DeviceIdError::Io { .. }));
    }
}
