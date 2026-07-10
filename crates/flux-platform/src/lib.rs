//! Linux and Android platform adapters for Flux.

use std::error::Error;
use std::fmt;

mod legacy_dispatcher;
mod seqpacket;

pub use legacy_dispatcher::{LegacyScriptPaths, ProcessLegacyDispatcher};
pub use seqpacket::{SeqpacketConnection, SeqpacketListener};

pub trait KernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemKernelReleaseSource;

impl KernelReleaseSource for SystemKernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError> {
        system_kernel_release()
    }
}

#[derive(Debug)]
pub enum PlatformError {
    UnsupportedPlatform(&'static str),
    SystemCall {
        operation: &'static str,
        source: std::io::Error,
    },
    InvalidKernelReleaseEncoding,
    InvalidSocketPath(String),
    PacketTooLarge {
        actual: usize,
        limit: usize,
    },
    PeerClosed,
    ShortWrite {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(formatter, "unsupported host platform '{platform}'")
            }
            Self::SystemCall { operation, source } => {
                write!(formatter, "{operation} failed: {source}")
            }
            Self::InvalidKernelReleaseEncoding => {
                formatter.write_str("kernel release is not valid UTF-8")
            }
            Self::InvalidSocketPath(message) => {
                write!(formatter, "invalid Unix socket path: {message}")
            }
            Self::PacketTooLarge { actual, limit } => {
                write!(formatter, "packet of {actual} bytes exceeds {limit} bytes")
            }
            Self::PeerClosed => formatter.write_str("control peer closed the connection"),
            Self::ShortWrite { expected, actual } => {
                write!(
                    formatter,
                    "short packet write: expected {expected} bytes, wrote {actual}"
                )
            }
        }
    }
}

impl Error for PlatformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SystemCall { source, .. } => Some(source),
            Self::UnsupportedPlatform(_)
            | Self::InvalidKernelReleaseEncoding
            | Self::InvalidSocketPath(_)
            | Self::PacketTooLarge { .. }
            | Self::PeerClosed
            | Self::ShortWrite { .. } => None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn system_kernel_release() -> Result<String, PlatformError> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    let mut name = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `name` points to writable storage for one `utsname`. A successful
    // `uname` call initializes the full structure before `assume_init`.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return Err(PlatformError::SystemCall {
            operation: "uname",
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: the successful `uname` call above initialized `name`.
    let name = unsafe { name.assume_init() };
    // SAFETY: POSIX specifies `release` as a NUL-terminated character array
    // within the initialized `utsname` value.
    let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
    release
        .to_str()
        .map(str::to_owned)
        .map_err(|_| PlatformError::InvalidKernelReleaseEncoding)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn system_kernel_release() -> Result<String, PlatformError> {
    Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
}
