use std::error::Error;
use std::fmt;

pub const MIN_SUPPORTED_KERNEL: KernelVersion = KernelVersion::new(5, 10, 0);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl KernelVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse_release(release: &str) -> Result<Self, ParseKernelVersionError> {
        let numeric = release
            .split_once('-')
            .map_or(release, |(prefix, _)| prefix);
        let mut components = numeric.split('.');

        let major = parse_required_component(components.next(), release, "major.minor")?;
        let minor = parse_required_component(components.next(), release, "major.minor")?;
        let patch = match components.next() {
            Some(value) if !value.is_empty() => value.parse::<u16>().map_err(|_| {
                ParseKernelVersionError::new(release, "expected numeric patch component")
            })?,
            _ => 0,
        };

        Ok(Self::new(major, minor, patch))
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    #[must_use]
    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelSupport {
    Supported(KernelVersion),
    Unsupported {
        found: KernelVersion,
        minimum: KernelVersion,
    },
}

impl KernelSupport {
    pub fn evaluate(release: &str) -> Result<Self, ParseKernelVersionError> {
        let found = KernelVersion::parse_release(release)?;
        if found < MIN_SUPPORTED_KERNEL {
            return Ok(Self::Unsupported {
                found,
                minimum: MIN_SUPPORTED_KERNEL,
            });
        }
        Ok(Self::Supported(found))
    }

    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseKernelVersionError {
    release: String,
    reason: &'static str,
}

impl ParseKernelVersionError {
    fn new(release: &str, reason: &'static str) -> Self {
        Self {
            release: release.to_owned(),
            reason,
        }
    }
}

impl fmt::Display for ParseKernelVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid kernel release '{}': {}",
            self.release, self.reason
        )
    }
}

impl Error for ParseKernelVersionError {}

fn parse_required_component(
    component: Option<&str>,
    release: &str,
    expectation: &'static str,
) -> Result<u16, ParseKernelVersionError> {
    component
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            ParseKernelVersionError::new(
                release,
                match expectation {
                    "major.minor" => "expected numeric major.minor",
                    _ => expectation,
                },
            )
        })
}
