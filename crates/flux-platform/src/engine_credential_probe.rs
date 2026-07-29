use std::ffi::{OsStr, OsString};
use std::num::{NonZeroU16, NonZeroU32};
use std::path::PathBuf;

use flux_core::{CaptureGroupId, CaptureUserId, EngineCredentials};

use crate::child_process::{
    TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK, TRANSPARENT_PROXY_ENGINE_SECUREBITS,
};
use crate::process::ProcessCredentials;

const CONFIG_BEGIN: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_CONFIG_BEGIN";
const CONFIG_END: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_CONFIG_END";
const REPORT_BEGIN: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_REPORT_BEGIN";
const REPORT_END: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_REPORT_END";
const MAX_CONFIG_BYTES: usize = 1024;
const MAX_REPORT_BYTES: usize = 4096;
const SOCKET_FIELDS: [&str; 4] = ["ipv4_tcp", "ipv6_tcp", "ipv4_udp", "ipv6_udp"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineCredentialProbeCommand {
    Version,
    Check {
        config: PathBuf,
        working_directory: PathBuf,
    },
    Run {
        config: PathBuf,
        working_directory: PathBuf,
    },
}

impl EngineCredentialProbeCommand {
    pub fn parse(arguments: &[OsString]) -> Result<Self, String> {
        match arguments {
            [_, command] if command == OsStr::new("version") => Ok(Self::Version),
            [
                _,
                command,
                config_flag,
                config,
                directory_flag,
                working_directory,
            ] if matches!(command.to_str(), Some("check" | "run"))
                && config_flag == OsStr::new("-c")
                && directory_flag == OsStr::new("-D") =>
            {
                let config = PathBuf::from(config);
                let working_directory = PathBuf::from(working_directory);
                if !config.is_absolute() || !working_directory.is_absolute() {
                    return Err(
                        "credential probe requires absolute config and working-directory paths"
                            .to_owned(),
                    );
                }
                if command == OsStr::new("check") {
                    Ok(Self::Check {
                        config,
                        working_directory,
                    })
                } else {
                    Ok(Self::Run {
                        config,
                        working_directory,
                    })
                }
            }
            _ => Err("expected version or check/run -c CONFIG -D WORKDIR".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineCredentialProbeConfig {
    credentials: EngineCredentials,
    listener_port: NonZeroU16,
    socket_mark: NonZeroU32,
    report_name: String,
}

impl EngineCredentialProbeConfig {
    pub fn new(
        credentials: EngineCredentials,
        listener_port: NonZeroU16,
        socket_mark: NonZeroU32,
        report_name: &str,
    ) -> Result<Self, String> {
        if !valid_report_name(report_name) {
            return Err("report must be one bounded relative ASCII filename".to_owned());
        }
        Ok(Self {
            credentials,
            listener_port,
            socket_mark,
            report_name: report_name.to_owned(),
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = framed_text(bytes, MAX_CONFIG_BYTES, "probe config")?;
        let mut lines = text.lines();
        require_line(&mut lines, CONFIG_BEGIN, "probe config")?;
        let uid = parse_u32(config_field(&mut lines, "uid")?, "probe config uid")?;
        let gid = parse_u32(config_field(&mut lines, "gid")?, "probe config gid")?;
        let uid =
            CaptureUserId::new(uid).ok_or_else(|| "probe config UID is reserved".to_owned())?;
        let gid =
            CaptureGroupId::new(gid).ok_or_else(|| "probe config GID is reserved".to_owned())?;
        let listener_port = NonZeroU16::new(parse_u16(
            config_field(&mut lines, "listener_port")?,
            "probe config listener_port",
        )?)
        .ok_or_else(|| "probe config listener_port must be nonzero".to_owned())?;
        let socket_mark = NonZeroU32::new(parse_u32(
            config_field(&mut lines, "socket_mark")?,
            "probe config socket_mark",
        )?)
        .ok_or_else(|| "probe config socket_mark must be nonzero".to_owned())?;
        let report_name = config_field(&mut lines, "report")?;
        require_line(&mut lines, CONFIG_END, "probe config")?;
        if lines.next().is_some() {
            return Err("probe config contains trailing fields".to_owned());
        }
        Self::new(
            EngineCredentials::new(uid, gid),
            listener_port,
            socket_mark,
            report_name,
        )
    }

    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{CONFIG_BEGIN}\nuid={}\ngid={}\nlistener_port={}\nsocket_mark={}\nreport={}\n{CONFIG_END}\n",
            self.credentials.uid().get(),
            self.credentials.gid().get(),
            self.listener_port,
            self.socket_mark,
            self.report_name,
        )
    }

    #[must_use]
    pub const fn credentials(&self) -> EngineCredentials {
        self.credentials
    }

    #[must_use]
    pub const fn listener_port(&self) -> NonZeroU16 {
        self.listener_port
    }

    #[must_use]
    pub const fn socket_mark(&self) -> NonZeroU32 {
        self.socket_mark
    }

    #[must_use]
    pub fn report_name(&self) -> &str {
        &self.report_name
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineCredentialProbeCapabilities {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineCredentialProbePrivilege {
    pub uids: [u32; 3],
    pub gids: [u32; 3],
    pub capabilities: EngineCredentialProbeCapabilities,
    pub securebits: u64,
    pub no_new_privileges: bool,
    pub parent_death_signal: i32,
}

impl EngineCredentialProbePrivilege {
    pub fn validate_for(self, expected: EngineCredentials) -> Result<(), String> {
        let uid = expected.uid().get();
        let gid = expected.gid().get();
        let mask = TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK;
        if self.uids != [uid; 3]
            || self.gids != [gid; 3]
            || self.capabilities.inheritable != mask
            || self.capabilities.permitted != mask
            || self.capabilities.effective != mask
            || self.capabilities.bounding != mask
            || self.capabilities.ambient != mask
            || self.securebits != TRANSPARENT_PROXY_ENGINE_SECUREBITS
            || !self.no_new_privileges
            || self.parent_death_signal != libc::SIGKILL
        {
            return Err("post-exec privilege contract mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineCredentialProbeReport {
    privilege: EngineCredentialProbePrivilege,
}

impl EngineCredentialProbeReport {
    #[must_use]
    pub const fn new(privilege: EngineCredentialProbePrivilege) -> Self {
        Self { privilege }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = framed_text(bytes, MAX_REPORT_BYTES, "credential-probe report")?;
        let mut lines = text.lines();
        require_line(&mut lines, REPORT_BEGIN, "credential-probe report")?;
        if report_field(&mut lines, "schema")? != "1" {
            return Err("credential-probe report schema is unsupported".to_owned());
        }
        let uids = [
            report_u32(&mut lines, "uid_real")?,
            report_u32(&mut lines, "uid_effective")?,
            report_u32(&mut lines, "uid_saved")?,
        ];
        let gids = [
            report_u32(&mut lines, "gid_real")?,
            report_u32(&mut lines, "gid_effective")?,
            report_u32(&mut lines, "gid_saved")?,
        ];
        if report_field(&mut lines, "supplementary_groups")? != "empty" {
            return Err("credential-probe supplementary groups are not empty".to_owned());
        }
        let capabilities = EngineCredentialProbeCapabilities {
            inheritable: report_hex(&mut lines, "capability_inheritable")?,
            permitted: report_hex(&mut lines, "capability_permitted")?,
            effective: report_hex(&mut lines, "capability_effective")?,
            bounding: report_hex(&mut lines, "capability_bounding")?,
            ambient: report_hex(&mut lines, "capability_ambient")?,
        };
        let securebits = report_u64(&mut lines, "securebits")?;
        let no_new_privileges = match report_field(&mut lines, "no_new_privileges")? {
            "1" => true,
            "0" => false,
            _ => return Err("credential-probe no-new-privileges is not binary".to_owned()),
        };
        let parent_death_signal = report_i32(&mut lines, "parent_death_signal")?;
        for socket in SOCKET_FIELDS {
            if report_field(&mut lines, socket)? != "transparent_marked" {
                return Err(format!("credential-probe {socket} evidence is incomplete"));
            }
        }
        require_line(&mut lines, REPORT_END, "credential-probe report")?;
        if lines.next().is_some() {
            return Err("credential-probe report contains trailing fields".to_owned());
        }
        Ok(Self::new(EngineCredentialProbePrivilege {
            uids,
            gids,
            capabilities,
            securebits,
            no_new_privileges,
            parent_death_signal,
        }))
    }

    #[must_use]
    pub fn render(self) -> String {
        let privilege = self.privilege;
        format!(
            "{REPORT_BEGIN}\n\
             schema=1\n\
             uid_real={}\n\
             uid_effective={}\n\
             uid_saved={}\n\
             gid_real={}\n\
             gid_effective={}\n\
             gid_saved={}\n\
             supplementary_groups=empty\n\
             capability_inheritable={:016x}\n\
             capability_permitted={:016x}\n\
             capability_effective={:016x}\n\
             capability_bounding={:016x}\n\
             capability_ambient={:016x}\n\
             securebits={}\n\
             no_new_privileges={}\n\
             parent_death_signal={}\n\
             ipv4_tcp=transparent_marked\n\
             ipv6_tcp=transparent_marked\n\
             ipv4_udp=transparent_marked\n\
             ipv6_udp=transparent_marked\n\
             {REPORT_END}\n",
            privilege.uids[0],
            privilege.uids[1],
            privilege.uids[2],
            privilege.gids[0],
            privilege.gids[1],
            privilege.gids[2],
            privilege.capabilities.inheritable,
            privilege.capabilities.permitted,
            privilege.capabilities.effective,
            privilege.capabilities.bounding,
            privilege.capabilities.ambient,
            privilege.securebits,
            u8::from(privilege.no_new_privileges),
            privilege.parent_death_signal,
        )
    }

    pub fn validate_for(self, expected: EngineCredentials) -> Result<(), String> {
        self.privilege.validate_for(expected)
    }
}

pub fn validate_engine_process_credentials(
    observed: &ProcessCredentials,
    expected: EngineCredentials,
) -> Result<(), String> {
    let uid = expected.uid().get();
    let gid = expected.gid().get();
    let mask = TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK;
    if observed.uids() != &[uid; 4]
        || observed.gids() != &[gid; 4]
        || !observed.supplementary_groups().is_empty()
        || observed.capability_inheritable() != mask
        || observed.capability_permitted() != mask
        || observed.capability_effective() != mask
        || observed.capability_bounding() != mask
        || observed.capability_ambient() != mask
        || !observed.no_new_privileges()
    {
        return Err("process-handle credential observation violates the exact contract".to_owned());
    }
    Ok(())
}

fn framed_text<'a>(bytes: &'a [u8], maximum: usize, label: &str) -> Result<&'a str, String> {
    if bytes.is_empty() || bytes.len() > maximum || bytes.contains(&0) {
        return Err(format!("{label} is empty, oversized, or contains NUL"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not valid UTF-8"))?;
    if text.contains('\r') || !text.ends_with('\n') {
        return Err(format!("{label} requires canonical LF framing"));
    }
    Ok(text)
}

fn require_line<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    if lines.next() == Some(expected) {
        Ok(())
    } else {
        Err(format!("{label} requires exact {expected} framing"))
    }
}

fn config_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
) -> Result<&'a str, String> {
    exact_field(lines, expected, "probe config")
}

fn report_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
) -> Result<&'a str, String> {
    exact_field(lines, expected, "credential-probe report")
}

fn exact_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
    label: &str,
) -> Result<&'a str, String> {
    let line = lines
        .next()
        .ok_or_else(|| format!("{label} is missing {expected}"))?;
    let (name, value) = line
        .split_once('=')
        .ok_or_else(|| format!("{label} field {expected} lacks '='"))?;
    if name != expected || value.is_empty() {
        return Err(format!("{label} requires exact field {expected}"));
    }
    Ok(value)
}

fn report_u32<'a>(lines: &mut impl Iterator<Item = &'a str>, field: &str) -> Result<u32, String> {
    parse_u32(report_field(lines, field)?, field)
}

fn report_u64<'a>(lines: &mut impl Iterator<Item = &'a str>, field: &str) -> Result<u64, String> {
    parse_u64(report_field(lines, field)?, field)
}

fn report_i32<'a>(lines: &mut impl Iterator<Item = &'a str>, field: &str) -> Result<i32, String> {
    let value = report_field(lines, field)?;
    if !canonical_decimal(value) {
        return Err(format!("credential-probe {field} is not canonical decimal"));
    }
    value
        .parse()
        .map_err(|_| format!("credential-probe {field} exceeds i32"))
}

fn report_hex<'a>(lines: &mut impl Iterator<Item = &'a str>, field: &str) -> Result<u64, String> {
    let value = report_field(lines, field)?;
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "credential-probe {field} is not exact lowercase hex"
        ));
    }
    u64::from_str_radix(value, 16).map_err(|_| format!("credential-probe {field} exceeds u64"))
}

fn parse_u16(value: &str, field: &str) -> Result<u16, String> {
    if !canonical_decimal(value) {
        return Err(format!("{field} is not canonical decimal"));
    }
    value.parse().map_err(|_| format!("{field} exceeds u16"))
}

fn parse_u32(value: &str, field: &str) -> Result<u32, String> {
    if !canonical_decimal(value) {
        return Err(format!("{field} is not canonical decimal"));
    }
    value.parse().map_err(|_| format!("{field} exceeds u32"))
}

fn parse_u64(value: &str, field: &str) -> Result<u64, String> {
    if !canonical_decimal(value) {
        return Err(format!("{field} is not canonical decimal"));
    }
    value.parse().map_err(|_| format!("{field} exceeds u64"))
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_report_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> EngineCredentials {
        EngineCredentials::new(
            CaptureUserId::new(0).expect("root UID"),
            CaptureGroupId::new(2000).expect("shell GID"),
        )
    }

    fn report() -> EngineCredentialProbeReport {
        let mask = TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK;
        EngineCredentialProbeReport::new(EngineCredentialProbePrivilege {
            uids: [0; 3],
            gids: [2000; 3],
            capabilities: EngineCredentialProbeCapabilities {
                inheritable: mask,
                permitted: mask,
                effective: mask,
                bounding: mask,
                ambient: mask,
            },
            securebits: TRANSPARENT_PROXY_ENGINE_SECUREBITS,
            no_new_privileges: true,
            parent_death_signal: libc::SIGKILL,
        })
    }

    #[test]
    fn command_requires_the_exact_production_adapter_shape() {
        let check = [
            "probe",
            "check",
            "-c",
            "/proc/self/fd/4",
            "-D",
            "/data/local/tmp/flux",
        ]
        .map(OsString::from);
        assert!(matches!(
            EngineCredentialProbeCommand::parse(&check),
            Ok(EngineCredentialProbeCommand::Check { .. })
        ));
        let run = [
            "probe",
            "run",
            "-c",
            "/proc/self/fd/4",
            "-D",
            "/data/local/tmp/flux",
        ]
        .map(OsString::from);
        assert!(matches!(
            EngineCredentialProbeCommand::parse(&run),
            Ok(EngineCredentialProbeCommand::Run { .. })
        ));
        assert_eq!(
            EngineCredentialProbeCommand::parse(&["probe", "version"].map(OsString::from)),
            Ok(EngineCredentialProbeCommand::Version)
        );
        assert!(
            EngineCredentialProbeCommand::parse(
                &["probe", "run", "-c", "/config"].map(OsString::from)
            )
            .is_err()
        );
        assert!(
            EngineCredentialProbeCommand::parse(
                &["probe", "run", "-c", "/config", "-D", "relative"].map(OsString::from)
            )
            .is_err()
        );
    }

    #[test]
    fn config_round_trip_is_canonical_and_rejects_path_escape() {
        let config = EngineCredentialProbeConfig::new(
            credentials(),
            NonZeroU16::new(12345).expect("port"),
            NonZeroU32::new(0x0100_0000).expect("mark"),
            "credential-device-gid-report",
        )
        .expect("config");
        let rendered = config.render();
        assert_eq!(
            EngineCredentialProbeConfig::parse(rendered.as_bytes()),
            Ok(config)
        );
        assert!(EngineCredentialProbeConfig::parse(rendered.trim_end().as_bytes()).is_err());
        assert!(
            EngineCredentialProbeConfig::new(
                credentials(),
                NonZeroU16::MIN,
                NonZeroU32::MIN,
                "../report",
            )
            .is_err()
        );
    }

    #[test]
    fn report_round_trip_validates_every_privilege_and_socket_field() {
        let report = report();
        let rendered = report.render();
        let parsed = EngineCredentialProbeReport::parse(rendered.as_bytes()).expect("report");
        assert_eq!(parsed, report);
        parsed.validate_for(credentials()).expect("exact contract");

        let wrong_capability = rendered.replacen(
            "capability_effective=0000000000003000",
            "capability_effective=0000000000001000",
            1,
        );
        assert!(
            EngineCredentialProbeReport::parse(wrong_capability.as_bytes())
                .expect("well-framed mismatch")
                .validate_for(credentials())
                .is_err()
        );
        let missing_socket =
            rendered.replacen("ipv6_udp=transparent_marked", "ipv6_udp=unavailable", 1);
        assert!(EngineCredentialProbeReport::parse(missing_socket.as_bytes()).is_err());
        assert!(
            EngineCredentialProbeReport::parse(format!("{rendered}trailing\n").as_bytes()).is_err()
        );
    }
}
