use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use local_transfer_core::device_name::DeviceName;
use local_transfer_core::identity::DeviceId;
use local_transfer_core::platform::Platform;
use local_transfer_core::{LocalDevice, LocalDeviceError, LocalDeviceManager};

#[derive(Debug, Parser, PartialEq)]
#[command(
    name = "local-transfer",
    version,
    about = "Local network file transfer"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, PartialEq, Subcommand)]
enum Command {
    /// Show this installation's local device identity.
    Device,
}

#[derive(Debug)]
struct DeviceView {
    id: DeviceId,
    name: DeviceName,
    platform: Platform,
}

impl From<LocalDevice> for DeviceView {
    fn from(device: LocalDevice) -> Self {
        Self {
            id: device.id(),
            name: device.name().clone(),
            platform: device.platform(),
        }
    }
}

#[derive(Debug)]
enum CliError {
    Load(LocalDeviceError),
    Output(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(source) => write!(formatter, "failed to load local device: {source}"),
            Self::Output(source) => write!(formatter, "failed to write command output: {source}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Load(source) => Some(source),
            Self::Output(source) => Some(source),
        }
    }
}

fn main() -> ExitCode {
    run_from(
        std::env::args_os(),
        load_current_device,
        io::stdout(),
        io::stderr(),
    )
}

fn load_current_device() -> Result<DeviceView, LocalDeviceError> {
    let manager = LocalDeviceManager::for_current_user()?;
    manager.load().map(Into::into)
}

fn run_from<I, T, L, W, E>(args: I, load: L, stdout: W, mut stderr: E) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    L: FnOnce() -> Result<DeviceView, LocalDeviceError>,
    W: Write,
    E: Write,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = write!(stderr, "{error}");
            return ExitCode::from(error.exit_code() as u8);
        }
    };

    match execute(cli.command, load, stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute<L, W>(command: Command, load: L, mut stdout: W) -> Result<(), CliError>
where
    L: FnOnce() -> Result<DeviceView, LocalDeviceError>,
    W: Write,
{
    match command {
        Command::Device => {
            let device = load().map_err(CliError::Load)?;
            writeln!(stdout, "ID:       {}", device.id).map_err(CliError::Output)?;
            writeln!(stdout, "Name:     {}", device.name).map_err(CliError::Output)?;
            writeln!(stdout, "Platform: {}", platform_label(device.platform))
                .map_err(CliError::Output)
        }
    }
}

const fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::MacOs => "macOS",
        Platform::Windows => "Windows",
        Platform::Linux => "Linux",
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use clap::Parser;
    use local_transfer_core::LocalDeviceError;
    use local_transfer_core::device_name::{
        DeviceName, DeviceNameError, DeviceNameValidationError,
    };
    use local_transfer_core::identity::DeviceId;
    use local_transfer_core::platform::Platform;

    use super::{Cli, CliError, Command, DeviceView, execute, platform_label, run_from};

    const DEVICE_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    fn device(platform: Platform) -> DeviceView {
        DeviceView {
            id: DeviceId::from_str(DEVICE_ID).unwrap(),
            name: DeviceName::new("Studio Workstation").unwrap(),
            platform,
        }
    }

    #[test]
    fn parses_device_command() {
        assert_eq!(
            Cli::try_parse_from(["local-transfer", "device"]).unwrap(),
            Cli {
                command: Command::Device
            }
        );
    }

    #[test]
    fn renders_device_id_name_and_platform() {
        let mut output = Vec::new();

        execute(Command::Device, || Ok(device(Platform::Linux)), &mut output).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "ID:       f47ac10b-58cc-4372-a567-0e02b2c3d479\n",
                "Name:     Studio Workstation\n",
                "Platform: Linux\n"
            )
        );
    }

    #[test]
    fn presents_human_facing_platform_labels() {
        assert_eq!(platform_label(Platform::MacOs), "macOS");
        assert_eq!(platform_label(Platform::Windows), "Windows");
        assert_eq!(platform_label(Platform::Linux), "Linux");
    }

    #[test]
    fn load_errors_propagate_with_their_domain_cause() {
        let error = execute(
            Command::Device,
            || {
                Err(LocalDeviceError::DeviceName(DeviceNameError::Validation(
                    DeviceNameValidationError::Empty,
                )))
            },
            Vec::new(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CliError::Load(LocalDeviceError::DeviceName(DeviceNameError::Validation(
                DeviceNameValidationError::Empty
            )))
        ));
    }

    #[test]
    fn successful_application_execution_uses_stdout_and_returns_success() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let status = run_from(
            ["local-transfer", "device"],
            || Ok(device(Platform::Linux)),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(status, std::process::ExitCode::SUCCESS);
        assert!(!stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn load_failure_uses_stderr_and_returns_failure() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let status = run_from(
            ["local-transfer", "device"],
            || Err(LocalDeviceError::ConfigDirectoryUnavailable),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(status, std::process::ExitCode::FAILURE);
        assert!(stdout.is_empty());
        let diagnostic = String::from_utf8(stderr).unwrap();
        assert!(diagnostic.contains("failed to load local device"));
        assert!(!diagnostic.contains("ConfigDirectoryUnavailable"));
    }

    #[test]
    fn unknown_command_returns_parser_usage_error() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let status = run_from(
            ["local-transfer", "peers"],
            || Ok(device(Platform::Linux)),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(status, std::process::ExitCode::from(2));
        assert!(stdout.is_empty());
        let diagnostic = String::from_utf8(stderr).unwrap();
        assert!(diagnostic.contains("Usage:"));
        assert!(diagnostic.contains("unrecognized subcommand"));
    }
}
