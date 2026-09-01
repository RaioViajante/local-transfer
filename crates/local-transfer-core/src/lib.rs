//! Shared domain library for local-transfer applications.

pub mod device_name;
pub mod identity;
pub mod platform;

mod persistence;

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
