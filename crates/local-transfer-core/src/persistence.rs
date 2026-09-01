use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

#[derive(Clone, Copy, Debug)]
pub(crate) enum PersistenceOperation {
    InspectDirectory,
    CreateDirectory,
    HardenDirectory,
    HardenFile,
    CreateTemporary,
    WriteTemporary,
    SyncTemporary,
}

#[derive(Debug)]
pub(crate) enum PersistenceError {
    InvalidPath {
        path: PathBuf,
    },
    Io {
        operation: PersistenceOperation,
        path: PathBuf,
        source: io::Error,
    },
}

pub(crate) fn harden_existing_file(path: &Path) -> Result<(), PersistenceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            set_file_permissions(path).map_err(|source| PersistenceError::Io {
                operation: PersistenceOperation::HardenFile,
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PersistenceError::Io {
            operation: PersistenceOperation::HardenFile,
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(crate) fn harden_existing_parent(destination: &Path) -> Result<(), PersistenceError> {
    let parent = destination
        .parent()
        .ok_or_else(|| PersistenceError::InvalidPath {
            path: destination.to_path_buf(),
        })?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() => {
            set_directory_permissions(parent).map_err(|source| PersistenceError::Io {
                operation: PersistenceOperation::HardenDirectory,
                path: parent.to_path_buf(),
                source,
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PersistenceError::Io {
            operation: PersistenceOperation::InspectDirectory,
            path: parent.to_path_buf(),
            source,
        }),
    }
}

pub(crate) fn create_synced_temporary(
    destination: &Path,
    contents: &[u8],
    harden_existing_parent: bool,
) -> Result<NamedTempFile, PersistenceError> {
    let parent = prepare_parent(destination, harden_existing_parent)?;
    let mut temporary = NamedTempFile::new_in(&parent).map_err(|source| PersistenceError::Io {
        operation: PersistenceOperation::CreateTemporary,
        path: parent,
        source,
    })?;
    set_open_file_permissions(temporary.as_file()).map_err(|source| PersistenceError::Io {
        operation: PersistenceOperation::HardenFile,
        path: temporary.path().to_path_buf(),
        source,
    })?;
    temporary
        .write_all(contents)
        .map_err(|source| PersistenceError::Io {
            operation: PersistenceOperation::WriteTemporary,
            path: temporary.path().to_path_buf(),
            source,
        })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| PersistenceError::Io {
            operation: PersistenceOperation::SyncTemporary,
            path: temporary.path().to_path_buf(),
            source,
        })?;
    Ok(temporary)
}

fn prepare_parent(
    destination: &Path,
    harden_existing_parent: bool,
) -> Result<PathBuf, PersistenceError> {
    let parent = destination
        .parent()
        .ok_or_else(|| PersistenceError::InvalidPath {
            path: destination.to_path_buf(),
        })?;
    let existing_directory = match fs::symlink_metadata(parent) {
        Ok(metadata) => Some(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(PersistenceError::Io {
                operation: PersistenceOperation::InspectDirectory,
                path: parent.to_path_buf(),
                source,
            });
        }
    };

    fs::create_dir_all(parent).map_err(|source| PersistenceError::Io {
        operation: PersistenceOperation::CreateDirectory,
        path: parent.to_path_buf(),
        source,
    })?;
    if existing_directory.is_none() || (harden_existing_parent && existing_directory == Some(true))
    {
        set_directory_permissions(parent).map_err(|source| PersistenceError::Io {
            operation: PersistenceOperation::HardenDirectory,
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(parent.to_path_buf())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_open_file_permissions(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_open_file_permissions(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::{create_synced_temporary, harden_existing_file, harden_existing_parent};

    #[test]
    fn newly_created_storage_uses_restrictive_permissions() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("local-transfer/device-id");

        let temporary = create_synced_temporary(&destination, b"identity\n", false).unwrap();
        temporary.persist(&destination).unwrap();

        let directory_mode = fs::metadata(destination.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(destination).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn broad_app_owned_permissions_are_tightened() {
        let directory = tempdir().unwrap();
        let app_directory = directory.path().join("local-transfer");
        let destination = app_directory.join("device-name");
        fs::create_dir(&app_directory).unwrap();
        fs::write(&destination, "Local Device\n").unwrap();
        fs::set_permissions(&app_directory, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o666)).unwrap();

        harden_existing_parent(&destination).unwrap();
        harden_existing_file(&destination).unwrap();

        let directory_mode = fs::metadata(app_directory).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(destination).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn existing_explicit_parent_permissions_are_not_changed() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("device-id");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();

        let temporary = create_synced_temporary(&destination, b"identity\n", false).unwrap();
        temporary.persist(&destination).unwrap();

        let directory_mode = fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(destination).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o755);
        assert_eq!(file_mode, 0o600);
    }
}
