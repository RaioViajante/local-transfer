//! Shared domain library for local-transfer applications.

pub mod advertisement;
pub mod device_name;
pub mod discovery;
pub mod identity;
mod local_device;
pub mod platform;

mod persistence;

pub use local_device::{LocalDevice, LocalDeviceError, LocalDeviceManager};

/// Returns the version of the shared core library.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn reports_package_version() {
        assert_eq!(super::version(), env!("CARGO_PKG_VERSION"));
    }
}
