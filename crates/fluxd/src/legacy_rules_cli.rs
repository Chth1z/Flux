use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use flux_platform::{
    LegacyApplicationMode, LegacyApplicationPolicy, LegacyInterfacePattern, LegacyInterfacePolicy,
    LegacyInterfaceRole, LegacyKernelFeatures, LegacyMarkValues, LegacyOwnerMatch,
    LegacyOwnerToken, LegacyRulesArtifactSet, LegacyRulesPlan, LegacyRulesRenderRequest,
    MAX_LEGACY_APPLICATION_UIDS, MAX_XTABLES_RESTORE_BYTES, XtablesRestoreAction,
    XtablesRestoreContext, XtablesRestoreFamily, render_legacy_rules_restore,
    render_legacy_rules_set,
};

use crate::legacy_rules_manifest::LegacyRulesSetManifest;

const EXIT_SUCCESS: i32 = 0;
const EXIT_RUNTIME_ERROR: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_UNSUPPORTED: i32 = 3;

const MAX_ENV_VALUE_BYTES: usize = 64 * 1024;
const MAX_PACKAGE_LIST_BYTES: usize = 4 * 1024 * 1024;
const MAX_PACKAGE_LIST_LINES: usize = 200_000;
const MAX_PACKAGE_LIST_LINE_BYTES: usize = 4096;
const MAX_PACKAGE_NAME_BYTES: usize = 255;
const ANDROID_UID_STRIDE: u32 = 100_000;
const MAX_ANDROID_USER_ID: u16 = 999;
const MAX_LEGACY_GENERATION: u32 = i32::MAX as u32;

pub trait LegacyRulesEnvironment {
    fn value(&self, name: &'static str) -> Option<OsString>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessLegacyRulesEnvironment;

impl LegacyRulesEnvironment for ProcessLegacyRulesEnvironment {
    fn value(&self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

pub fn run_legacy_rules_cli<I, T, O, E>(
    args: I,
    environment: &impl LegacyRulesEnvironment,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    match render_from_inputs(args, environment) {
        Ok(bytes) => match stdout.write_all(&bytes) {
            Ok(()) => EXIT_SUCCESS,
            Err(error) => {
                let _ = writeln!(stderr, "fluxd: cannot write rendered rules: {error}");
                EXIT_RUNTIME_ERROR
            }
        },
        Err(LegacyRulesCliError::Usage(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            let _ = writeln!(stderr, "{}", usage());
            EXIT_USAGE
        }
        Err(LegacyRulesCliError::Unsupported(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            EXIT_UNSUPPORTED
        }
        Err(LegacyRulesCliError::Input(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            EXIT_RUNTIME_ERROR
        }
    }
}

pub fn run_legacy_package_snapshot_cli<I, T, O, E>(args: I, stdout: &mut O, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    match snapshot_from_inputs(args) {
        Ok(bytes) => match stdout.write_all(&bytes) {
            Ok(()) => EXIT_SUCCESS,
            Err(error) => {
                let _ = writeln!(stderr, "fluxd: cannot write package snapshot: {error}");
                EXIT_RUNTIME_ERROR
            }
        },
        Err(LegacyRulesCliError::Usage(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            let _ = writeln!(stderr, "{}", snapshot_usage());
            EXIT_USAGE
        }
        Err(LegacyRulesCliError::Unsupported(message))
        | Err(LegacyRulesCliError::Input(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            EXIT_RUNTIME_ERROR
        }
    }
}

pub fn run_legacy_rules_attestation_cli<I, T, O, E>(
    args: I,
    environment: &impl LegacyRulesEnvironment,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    match attest_from_inputs(args, environment) {
        Ok(bytes) => match stdout.write_all(&bytes) {
            Ok(()) => EXIT_SUCCESS,
            Err(error) => {
                let _ = writeln!(stderr, "fluxd: cannot write legacy rules manifest: {error}");
                EXIT_RUNTIME_ERROR
            }
        },
        Err(LegacyRulesCliError::Usage(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            let _ = writeln!(stderr, "{}", attestation_usage());
            EXIT_USAGE
        }
        Err(LegacyRulesCliError::Unsupported(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            EXIT_UNSUPPORTED
        }
        Err(LegacyRulesCliError::Input(message)) => {
            let _ = writeln!(stderr, "fluxd: {message}");
            EXIT_RUNTIME_ERROR
        }
    }
}

fn render_from_inputs<I, T>(
    args: I,
    environment: &impl LegacyRulesEnvironment,
) -> Result<Box<[u8]>, LegacyRulesCliError>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let request = CliRequest::parse(args)?;
    let values = EnvironmentValues::read(environment)?;
    values.require_supported_bridge()?;
    let ordered_uids = values.resolve_application_uids(&request.packages_list, request.action)?;
    let plan = values.build_plan(ordered_uids)?;
    if !plan.production_eligible() {
        return Err(LegacyRulesCliError::Unsupported(
            "legacy renderer requires active xt_owner and TPROXY support".to_owned(),
        ));
    }
    let context = XtablesRestoreContext::new(request.action, request.family);
    let artifact = render_legacy_rules_restore(LegacyRulesRenderRequest::new(context, &plan))
        .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?;
    Ok(artifact.render_canonical())
}

fn snapshot_from_inputs<I, T>(args: I) -> Result<Box<[u8]>, LegacyRulesCliError>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let path = SnapshotRequest::parse(args)?;
    read_packages_list_bytes(&path.source)
}

fn attest_from_inputs<I, T>(
    args: I,
    environment: &impl LegacyRulesEnvironment,
) -> Result<Box<[u8]>, LegacyRulesCliError>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let request = AttestationRequest::parse(args)?;
    let values = EnvironmentValues::read(environment)?;
    values.require_supported_bridge()?;
    request.require_family_shape(values.ipv6_enabled)?;
    let ordered_uids =
        values.resolve_application_uids(&request.packages_list, XtablesRestoreAction::Apply)?;
    let plan = values.build_plan(ordered_uids)?;
    if !plan.production_eligible() {
        return Err(LegacyRulesCliError::Unsupported(
            "legacy renderer requires active xt_owner and TPROXY support".to_owned(),
        ));
    }
    let artifacts = render_legacy_rules_set(&plan)
        .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?;
    request.require_exact_artifacts(&artifacts)?;
    let manifest = LegacyRulesSetManifest::from_artifact_set(request.generation, &artifacts)
        .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?;
    manifest
        .verify(request.generation, &artifacts)
        .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?;
    Ok(manifest.render_canonical())
}

const fn usage() -> &'static str {
    "Usage: fluxd render-legacy-rules --packages-list PATH --family 4|6 --action apply|cleanup"
}

const fn snapshot_usage() -> &'static str {
    "Usage: fluxd snapshot-legacy-packages --source PATH"
}

const fn attestation_usage() -> &'static str {
    "Usage: fluxd attest-legacy-rules-set --generation ID --packages-list PATH --ipv4-apply PATH --ipv4-cleanup PATH [--ipv6-apply PATH --ipv6-cleanup PATH]"
}

struct SnapshotRequest {
    source: PathBuf,
}

impl SnapshotRequest {
    fn parse<I, T>(args: I) -> Result<Self, LegacyRulesCliError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut args = args.into_iter();
        let _program = args.next();
        let Some(command) = args.next() else {
            return Err(LegacyRulesCliError::Usage(
                "snapshot-legacy-packages command is missing".to_owned(),
            ));
        };
        if command.as_ref() != "snapshot-legacy-packages" {
            return Err(LegacyRulesCliError::Usage(format!(
                "expected snapshot-legacy-packages, found '{}'",
                command.as_ref()
            )));
        }
        let Some(flag) = args.next() else {
            return Err(LegacyRulesCliError::Usage(
                "--source is required".to_owned(),
            ));
        };
        if flag.as_ref() != "--source" {
            return Err(LegacyRulesCliError::Usage(format!(
                "unknown snapshot-legacy-packages option '{}'",
                flag.as_ref()
            )));
        }
        let Some(source) = args.next() else {
            return Err(LegacyRulesCliError::Usage(
                "--source requires a value".to_owned(),
            ));
        };
        if source.as_ref().is_empty() {
            return Err(LegacyRulesCliError::Usage(
                "--source must not be empty".to_owned(),
            ));
        }
        if let Some(extra) = args.next() {
            return Err(LegacyRulesCliError::Usage(format!(
                "unexpected snapshot-legacy-packages argument '{}'",
                extra.as_ref()
            )));
        }
        Ok(Self {
            source: PathBuf::from(source.as_ref()),
        })
    }
}

struct AttestationRequest {
    generation: NonZeroU32,
    packages_list: PathBuf,
    ipv4_apply: PathBuf,
    ipv4_cleanup: PathBuf,
    ipv6_apply: Option<PathBuf>,
    ipv6_cleanup: Option<PathBuf>,
}

impl AttestationRequest {
    fn parse<I, T>(args: I) -> Result<Self, LegacyRulesCliError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut args = args.into_iter();
        let _program = args.next();
        let Some(command) = args.next() else {
            return Err(LegacyRulesCliError::Usage(
                "attest-legacy-rules-set command is missing".to_owned(),
            ));
        };
        if command.as_ref() != "attest-legacy-rules-set" {
            return Err(LegacyRulesCliError::Usage(format!(
                "expected attest-legacy-rules-set, found '{}'",
                command.as_ref()
            )));
        }

        let mut fields = HashMap::<&str, String>::new();
        while let Some(flag) = args.next() {
            let flag = match flag.as_ref() {
                "--generation" => "--generation",
                "--packages-list" => "--packages-list",
                "--ipv4-apply" => "--ipv4-apply",
                "--ipv4-cleanup" => "--ipv4-cleanup",
                "--ipv6-apply" => "--ipv6-apply",
                "--ipv6-cleanup" => "--ipv6-cleanup",
                unknown => {
                    return Err(LegacyRulesCliError::Usage(format!(
                        "unknown attest-legacy-rules-set option '{unknown}'"
                    )));
                }
            };
            let Some(value) = args.next() else {
                return Err(LegacyRulesCliError::Usage(format!(
                    "{flag} requires a value"
                )));
            };
            if fields.insert(flag, value.as_ref().to_owned()).is_some() {
                return Err(LegacyRulesCliError::Usage(format!(
                    "{flag} was specified more than once"
                )));
            }
        }

        let generation_text = required_flag(&fields, "--generation")?;
        let generation = parse_cli_generation(generation_text)?;
        let packages_list = required_path(&fields, "--packages-list")?;
        let ipv4_apply = required_path(&fields, "--ipv4-apply")?;
        let ipv4_cleanup = required_path(&fields, "--ipv4-cleanup")?;
        let ipv6_apply = optional_path(&fields, "--ipv6-apply")?;
        let ipv6_cleanup = optional_path(&fields, "--ipv6-cleanup")?;

        Ok(Self {
            generation,
            packages_list,
            ipv4_apply,
            ipv4_cleanup,
            ipv6_apply,
            ipv6_cleanup,
        })
    }

    fn require_family_shape(&self, ipv6_enabled: bool) -> Result<(), LegacyRulesCliError> {
        match (
            ipv6_enabled,
            self.ipv6_apply.is_some(),
            self.ipv6_cleanup.is_some(),
        ) {
            (true, true, true) | (false, false, false) => Ok(()),
            (true, _, _) => Err(LegacyRulesCliError::Usage(
                "PROXY_IPV6=1 requires both --ipv6-apply and --ipv6-cleanup".to_owned(),
            )),
            (false, _, _) => Err(LegacyRulesCliError::Usage(
                "PROXY_IPV6=0 forbids --ipv6-apply and --ipv6-cleanup".to_owned(),
            )),
        }
    }

    fn require_exact_artifacts(
        &self,
        artifacts: &LegacyRulesArtifactSet,
    ) -> Result<(), LegacyRulesCliError> {
        require_exact_artifact(&self.ipv4_apply, "IPv4 apply", artifacts.ipv4().apply())?;
        require_exact_artifact(
            &self.ipv4_cleanup,
            "IPv4 cleanup",
            artifacts.ipv4().cleanup(),
        )?;
        match (
            self.ipv6_apply.as_deref(),
            self.ipv6_cleanup.as_deref(),
            artifacts.ipv6(),
        ) {
            (Some(apply), Some(cleanup), Some(ipv6)) => {
                require_exact_artifact(apply, "IPv6 apply", ipv6.apply())?;
                require_exact_artifact(cleanup, "IPv6 cleanup", ipv6.cleanup())
            }
            (None, None, None) => Ok(()),
            _ => Err(LegacyRulesCliError::Input(
                "legacy rules artifact family shape does not match the prepared plan".to_owned(),
            )),
        }
    }
}

fn parse_cli_generation(value: &str) -> Result<NonZeroU32, LegacyRulesCliError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|generation| {
            (1..=MAX_LEGACY_GENERATION).contains(generation)
                && generation.to_string() == value
                && value.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(NonZeroU32::new)
        .ok_or_else(|| {
            LegacyRulesCliError::Usage(
                "--generation must be a canonical integer in 1..=2147483647".to_owned(),
            )
        })
}

fn required_path(
    fields: &HashMap<&str, String>,
    name: &'static str,
) -> Result<PathBuf, LegacyRulesCliError> {
    let value = required_flag(fields, name)?;
    if value.is_empty() {
        Err(LegacyRulesCliError::Usage(format!(
            "{name} must not be empty"
        )))
    } else {
        Ok(PathBuf::from(value))
    }
}

fn optional_path(
    fields: &HashMap<&str, String>,
    name: &'static str,
) -> Result<Option<PathBuf>, LegacyRulesCliError> {
    fields
        .get(name)
        .map(|_| required_path(fields, name))
        .transpose()
}

struct CliRequest {
    packages_list: PathBuf,
    family: XtablesRestoreFamily,
    action: XtablesRestoreAction,
}

impl CliRequest {
    fn parse<I, T>(args: I) -> Result<Self, LegacyRulesCliError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut args = args.into_iter();
        let _program = args.next();
        let Some(command) = args.next() else {
            return Err(LegacyRulesCliError::Usage(
                "render-legacy-rules command is missing".to_owned(),
            ));
        };
        if command.as_ref() != "render-legacy-rules" {
            return Err(LegacyRulesCliError::Usage(format!(
                "expected render-legacy-rules, found '{}'",
                command.as_ref()
            )));
        }

        let mut fields = HashMap::<&str, String>::new();
        while let Some(flag) = args.next() {
            let flag = match flag.as_ref() {
                "--packages-list" => "--packages-list",
                "--family" => "--family",
                "--action" => "--action",
                unknown => {
                    return Err(LegacyRulesCliError::Usage(format!(
                        "unknown render-legacy-rules option '{unknown}'"
                    )));
                }
            };
            let Some(value) = args.next() else {
                return Err(LegacyRulesCliError::Usage(format!(
                    "{flag} requires a value"
                )));
            };
            if fields.insert(flag, value.as_ref().to_owned()).is_some() {
                return Err(LegacyRulesCliError::Usage(format!(
                    "{flag} was specified more than once"
                )));
            }
        }

        let packages_list = required_flag(&fields, "--packages-list")?;
        if packages_list.is_empty() {
            return Err(LegacyRulesCliError::Usage(
                "--packages-list must not be empty".to_owned(),
            ));
        }
        let family = match required_flag(&fields, "--family")? {
            "4" => XtablesRestoreFamily::Ipv4,
            "6" => XtablesRestoreFamily::Ipv6,
            value => {
                return Err(LegacyRulesCliError::Usage(format!(
                    "invalid --family value '{value}'"
                )));
            }
        };
        let action = match required_flag(&fields, "--action")? {
            "apply" => XtablesRestoreAction::Apply,
            "cleanup" => XtablesRestoreAction::Cleanup,
            value => {
                return Err(LegacyRulesCliError::Usage(format!(
                    "invalid --action value '{value}'"
                )));
            }
        };
        Ok(Self {
            packages_list: PathBuf::from(packages_list),
            family,
            action,
        })
    }
}

fn required_flag<'a>(
    fields: &'a HashMap<&str, String>,
    name: &'static str,
) -> Result<&'a str, LegacyRulesCliError> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| LegacyRulesCliError::Usage(format!("{name} is required")))
}

struct EnvironmentValues {
    proxy_mode: String,
    rule_backend: String,
    bypass_backend: String,
    proxy_port: u16,
    mark_mask: u32,
    marks: LegacyMarkValues,
    routing_mark: Option<u32>,
    core_user: String,
    core_group: String,
    app_mode: LegacyApplicationMode,
    app_list: Box<[String]>,
    app_user_scope: ApplicationUserScope,
    app_user_list: Box<[u16]>,
    excluded_interfaces: Box<[String]>,
    roles: [(Option<String>, bool); 4],
    performance_mode: bool,
    mss_clamp: bool,
    ipv6_enabled: bool,
    fake_ip_v4: String,
    fake_ip_v6: String,
    features: LegacyKernelFeatures,
    owner_feature: bool,
    tproxy_feature: bool,
}

impl EnvironmentValues {
    fn read(environment: &impl LegacyRulesEnvironment) -> Result<Self, LegacyRulesCliError> {
        let proxy_mode = required_environment(environment, "PROXY_MODE")?;
        let rule_backend = required_environment(environment, "RULE_BACKEND")?;
        let bypass_backend = required_environment(environment, "BYPASS_SET_BACKEND")?;
        let proxy_port = parse_decimal::<u16>(
            "PROXY_PORT",
            &required_environment(environment, "PROXY_PORT")?,
        )?;
        if proxy_port == 0 {
            return Err(invalid_environment("PROXY_PORT", "must be in 1..=65535"));
        }
        let mark_mask = parse_mark(
            "MARK_MASK",
            &required_environment(environment, "MARK_MASK")?,
        )?;
        let marks = LegacyMarkValues::new(
            parse_mark(
                "IPV4_MARK",
                &required_environment(environment, "IPV4_MARK")?,
            )?,
            parse_mark(
                "IPV6_MARK",
                &required_environment(environment, "IPV6_MARK")?,
            )?,
            parse_mark(
                "BYPASS_MARK",
                &required_environment(environment, "BYPASS_MARK")?,
            )?,
        );
        let routing_mark_text = required_environment(environment, "ROUTING_MARK")?;
        let routing_mark = if routing_mark_text.is_empty() {
            None
        } else {
            Some(parse_decimal::<u16>("ROUTING_MARK", &routing_mark_text)?.into())
        };
        let core_user =
            validate_owner("CORE_USER", required_environment(environment, "CORE_USER")?)?;
        let core_group = validate_owner(
            "CORE_GROUP",
            required_environment(environment, "CORE_GROUP")?,
        )?;
        let app_mode = match required_environment(environment, "APP_PROXY_MODE")?.as_str() {
            "0" => LegacyApplicationMode::All,
            "1" => LegacyApplicationMode::Denylist,
            "2" => LegacyApplicationMode::Allowlist,
            _ => {
                return Err(invalid_environment(
                    "APP_PROXY_MODE",
                    "expected exactly 0, 1, or 2",
                ));
            }
        };
        let app_list =
            parse_package_names("APP_LIST", &required_environment(environment, "APP_LIST")?)?;
        let app_user_scope = match required_environment(environment, "APP_USER_SCOPE")?.as_str() {
            "owner" => ApplicationUserScope::Owner,
            "all" => ApplicationUserScope::All,
            "list" => ApplicationUserScope::List,
            _ => {
                return Err(invalid_environment(
                    "APP_USER_SCOPE",
                    "expected exactly owner, all, or list",
                ));
            }
        };
        let app_user_list = parse_user_list(&required_environment(environment, "APP_USER_LIST")?)?;
        let excluded_interfaces = parse_interfaces(
            "EXCLUDE_INTERFACES",
            &required_environment(environment, "EXCLUDE_INTERFACES")?,
        )?;
        let roles = [
            read_role(environment, "MOBILE_INTERFACE", "PROXY_MOBILE")?,
            read_role(environment, "WIFI_INTERFACE", "PROXY_WIFI")?,
            read_role(environment, "HOTSPOT_INTERFACE", "PROXY_HOTSPOT")?,
            read_role(environment, "USB_INTERFACE", "PROXY_USB")?,
        ];
        let performance_mode = parse_bool(environment, "PERFORMANCE_MODE")?;
        let mss_clamp = parse_bool(environment, "MSS_CLAMP_ENABLE")?;
        let ipv6_enabled = parse_bool(environment, "PROXY_IPV6")?;
        let fake_ip_v4 = required_environment(environment, "FAKEIP_V4_RANGE")?;
        let fake_ip_v6 = required_environment(environment, "FAKEIP_V6_RANGE")?;
        let owner_feature = parse_bool(environment, "KFEAT_OWNER")?;
        let mark = parse_bool(environment, "KFEAT_MARK")?;
        let conntrack = parse_bool(environment, "KFEAT_CONNTRACK")?;
        let socket_tcp = parse_bool(environment, "KFEAT_SOCKET_TCP")?;
        let socket_udp = parse_bool(environment, "KFEAT_SOCKET_UDP")?;
        let ipv6_nat = parse_bool(environment, "KFEAT_IPV6_NAT")?;
        let tproxy_feature = parse_bool(environment, "KFEAT_TPROXY")?;
        let features = LegacyKernelFeatures::new(
            owner_feature,
            mark,
            conntrack,
            socket_tcp,
            socket_udp,
            ipv6_nat,
            tproxy_feature,
        );
        Ok(Self {
            proxy_mode,
            rule_backend,
            bypass_backend,
            proxy_port,
            mark_mask,
            marks,
            routing_mark,
            core_user,
            core_group,
            app_mode,
            app_list,
            app_user_scope,
            app_user_list,
            excluded_interfaces,
            roles,
            performance_mode,
            mss_clamp,
            ipv6_enabled,
            fake_ip_v4,
            fake_ip_v6,
            features,
            owner_feature,
            tproxy_feature,
        })
    }

    fn require_supported_bridge(&self) -> Result<(), LegacyRulesCliError> {
        for (actual, expected, label) in [
            (self.proxy_mode.as_str(), "tproxy", "PROXY_MODE"),
            (
                self.rule_backend.as_str(),
                "iptables_restore",
                "RULE_BACKEND",
            ),
            (self.bypass_backend.as_str(), "zone", "BYPASS_SET_BACKEND"),
        ] {
            if actual != expected {
                return Err(LegacyRulesCliError::Unsupported(format!(
                    "{label}={actual} is unsupported by the Rust legacy renderer"
                )));
            }
        }
        if !self.owner_feature {
            return Err(LegacyRulesCliError::Unsupported(
                "KFEAT_OWNER=0 is unsupported by the production bridge".to_owned(),
            ));
        }
        if !self.tproxy_feature {
            return Err(LegacyRulesCliError::Unsupported(
                "KFEAT_TPROXY=0 is unsupported by the production bridge".to_owned(),
            ));
        }
        if self.mark_mask != 0xff {
            return Err(LegacyRulesCliError::Unsupported(format!(
                "MARK_MASK=0x{:x} is unsupported; the production bridge admits exactly 0xff",
                self.mark_mask
            )));
        }
        Ok(())
    }

    fn resolve_application_uids(
        &self,
        path: &Path,
        action: XtablesRestoreAction,
    ) -> Result<Vec<u32>, LegacyRulesCliError> {
        if action == XtablesRestoreAction::Cleanup
            || self.app_mode == LegacyApplicationMode::All
            || self.app_list.is_empty()
        {
            return Ok(Vec::new());
        }
        let target_packages = self
            .app_list
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let users = match self.app_user_scope {
            ApplicationUserScope::Owner => vec![0],
            ApplicationUserScope::All => (0..=99).collect(),
            ApplicationUserScope::List => self
                .app_user_list
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        let contents = read_packages_list(path)?;
        resolve_package_uids(&contents, &target_packages, &users)
    }

    fn build_plan(&self, ordered_uids: Vec<u32>) -> Result<LegacyRulesPlan, LegacyRulesCliError> {
        let pattern = |value: &str| {
            LegacyInterfacePattern::new(value)
                .map_err(|error| LegacyRulesCliError::Input(error.to_string()))
        };
        let excluded = self
            .excluded_interfaces
            .iter()
            .map(|value| pattern(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut roles = Vec::with_capacity(self.roles.len());
        for (value, proxy) in &self.roles {
            roles.push(LegacyInterfaceRole::new(
                value.as_deref().map(pattern).transpose()?,
                *proxy,
            ));
        }
        let [mobile, wifi, hotspot, usb]: [LegacyInterfaceRole; 4] = roles
            .try_into()
            .expect("the fixed legacy role set always contains four entries");
        let interfaces = LegacyInterfacePolicy::new(excluded, mobile, wifi, hotspot, usb)
            .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?;
        let owner = LegacyOwnerMatch::new(
            LegacyOwnerToken::new(&self.core_user)
                .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?,
            LegacyOwnerToken::new(&self.core_group)
                .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?,
        );
        let applications = LegacyApplicationPolicy::new(self.app_mode, ordered_uids)
            .map_err(|error| LegacyRulesCliError::Input(error.to_string()))?;
        LegacyRulesPlan::new(
            self.proxy_port,
            self.mark_mask,
            self.marks,
            self.routing_mark,
            owner,
            applications,
            interfaces,
            self.features,
            self.performance_mode,
            self.mss_clamp,
            self.ipv6_enabled,
            &self.fake_ip_v4,
            &self.fake_ip_v6,
        )
        .map_err(|error| LegacyRulesCliError::Input(error.to_string()))
    }
}

#[derive(Clone, Copy)]
enum ApplicationUserScope {
    Owner,
    All,
    List,
}

fn required_environment(
    environment: &impl LegacyRulesEnvironment,
    name: &'static str,
) -> Result<String, LegacyRulesCliError> {
    let value = environment
        .value(name)
        .ok_or_else(|| invalid_environment(name, "is required"))?;
    let value = value
        .into_string()
        .map_err(|_| invalid_environment(name, "must be valid UTF-8"))?;
    if value.len() > MAX_ENV_VALUE_BYTES || value.contains(['\0', '\r', '\n']) {
        return Err(invalid_environment(
            name,
            "exceeds its bound or contains a forbidden control character",
        ));
    }
    Ok(value)
}

fn parse_bool(
    environment: &impl LegacyRulesEnvironment,
    name: &'static str,
) -> Result<bool, LegacyRulesCliError> {
    match required_environment(environment, name)?.as_str() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(invalid_environment(name, "expected exactly 0 or 1")),
    }
}

fn parse_decimal<T>(name: &'static str, value: &str) -> Result<T, LegacyRulesCliError>
where
    T: std::str::FromStr,
{
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_environment(
            name,
            "expected unsigned decimal digits",
        ));
    }
    value
        .parse::<T>()
        .map_err(|_| invalid_environment(name, "numeric value is out of range"))
}

fn parse_mark(name: &'static str, value: &str) -> Result<u32, LegacyRulesCliError> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_environment(
                name,
                "expected decimal or 0x hexadecimal mark",
            ));
        }
        u32::from_str_radix(hex, 16)
    } else {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_environment(
                name,
                "expected decimal or 0x hexadecimal mark",
            ));
        }
        value.parse::<u32>()
    }
    .map_err(|_| invalid_environment(name, "mark is out of range"))?;
    if parsed == 0 {
        return Err(invalid_environment(name, "must be nonzero"));
    }
    Ok(parsed)
}

fn validate_owner(name: &'static str, value: String) -> Result<String, LegacyRulesCliError> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        let _ = parse_decimal::<u32>(name, &value)?;
    }
    LegacyOwnerToken::new(&value).map_err(|_| {
        invalid_environment(name, "expected a u32 decimal ID or safe ASCII owner name")
    })?;
    Ok(value)
}

fn parse_package_names(
    name: &'static str,
    value: &str,
) -> Result<Box<[String]>, LegacyRulesCliError> {
    value
        .split_ascii_whitespace()
        .map(|package| {
            validate_package_name(package)
                .map(|()| package.to_owned())
                .map_err(|reason| invalid_environment(name, reason))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn parse_user_list(value: &str) -> Result<Box<[u16]>, LegacyRulesCliError> {
    value
        .split_ascii_whitespace()
        .map(|user| {
            let user = parse_decimal::<u16>("APP_USER_LIST", user)?;
            if user > MAX_ANDROID_USER_ID {
                return Err(invalid_environment(
                    "APP_USER_LIST",
                    "Android user ID must be in 0..=999",
                ));
            }
            Ok(user)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn parse_interfaces(name: &'static str, value: &str) -> Result<Box<[String]>, LegacyRulesCliError> {
    value
        .split_ascii_whitespace()
        .map(|interface| {
            LegacyInterfacePattern::new(interface)
                .map(|_| interface.to_owned())
                .map_err(|_| invalid_environment(name, "contains an invalid interface pattern"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn read_role(
    environment: &impl LegacyRulesEnvironment,
    interface_name: &'static str,
    enabled_name: &'static str,
) -> Result<(Option<String>, bool), LegacyRulesCliError> {
    let value = required_environment(environment, interface_name)?;
    let pattern = if value.is_empty() {
        None
    } else {
        LegacyInterfacePattern::new(&value).map_err(|_| {
            invalid_environment(interface_name, "contains an invalid interface pattern")
        })?;
        Some(value)
    };
    Ok((pattern, parse_bool(environment, enabled_name)?))
}

fn read_packages_list(path: &Path) -> Result<String, LegacyRulesCliError> {
    let bytes = read_packages_list_bytes(path)?;
    Ok(String::from_utf8(bytes.into_vec())
        .expect("the shared package snapshot reader validated UTF-8"))
}

fn read_packages_list_bytes(path: &Path) -> Result<Box<[u8]>, LegacyRulesCliError> {
    let bytes = read_bounded_stable_bytes(path, "packages list", MAX_PACKAGE_LIST_BYTES)?;
    std::str::from_utf8(&bytes).map_err(|_| {
        LegacyRulesCliError::Input(format!(
            "packages list '{}' is not valid UTF-8",
            path.display()
        ))
    })?;
    Ok(bytes)
}

fn require_exact_artifact(
    path: &Path,
    label: &'static str,
    expected: &flux_platform::XtablesRestoreArtifact,
) -> Result<(), LegacyRulesCliError> {
    let purpose = format!("{label} restore artifact");
    let actual = read_bounded_stable_bytes(path, &purpose, MAX_XTABLES_RESTORE_BYTES)?;
    if actual.as_ref() == expected.render_canonical().as_ref() {
        Ok(())
    } else {
        Err(LegacyRulesCliError::Input(format!(
            "{purpose} '{}' does not exactly match canonical Rust output",
            path.display()
        )))
    }
}

fn read_bounded_stable_bytes(
    path: &Path,
    purpose: &str,
    max_bytes: usize,
) -> Result<Box<[u8]>, LegacyRulesCliError> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        LegacyRulesCliError::Input(format!(
            "cannot inspect {purpose} '{}': {error}",
            path.display()
        ))
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(LegacyRulesCliError::Input(format!(
            "{purpose} '{}' must be a regular non-symlink file",
            path.display()
        )));
    }
    if before.len() > max_bytes as u64 {
        return Err(LegacyRulesCliError::Input(format!(
            "{purpose} '{}' exceeds {max_bytes} bytes",
            path.display()
        )));
    }
    let file = open_bounded_input(path).map_err(|error| {
        LegacyRulesCliError::Input(format!(
            "cannot open {purpose} '{}': {error}",
            path.display()
        ))
    })?;
    let opened = file.metadata().map_err(|error| {
        LegacyRulesCliError::Input(format!(
            "cannot inspect opened {purpose} '{}': {error}",
            path.display()
        ))
    })?;
    if !opened.is_file() || opened.len() > max_bytes as u64 {
        return Err(LegacyRulesCliError::Input(format!(
            "opened {purpose} '{}' is not an admitted regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(LegacyRulesCliError::Input(format!(
                "{purpose} '{}' changed while it was opened",
                path.display()
            )));
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LegacyRulesCliError::Input(format!(
                "cannot read {purpose} '{}': {error}",
                path.display()
            ))
        })?;
    if bytes.len() > max_bytes {
        return Err(LegacyRulesCliError::Input(format!(
            "{purpose} '{}' grew beyond {max_bytes} bytes",
            path.display()
        )));
    }
    let after = file.metadata().map_err(|error| {
        LegacyRulesCliError::Input(format!(
            "cannot re-inspect {purpose} '{}': {error}",
            path.display()
        ))
    })?;
    if !input_metadata_is_stable(&opened, &after) {
        return Err(LegacyRulesCliError::Input(format!(
            "{purpose} '{}' changed while it was read",
            path.display()
        )));
    }
    Ok(bytes.into_boxed_slice())
}

#[cfg(unix)]
fn input_metadata_is_stable(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn input_metadata_is_stable(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn open_bounded_input(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn resolve_package_uids(
    contents: &str,
    targets: &BTreeSet<&str>,
    users: &[u16],
) -> Result<Vec<u32>, LegacyRulesCliError> {
    let mut ordered = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if index >= MAX_PACKAGE_LIST_LINES {
            return Err(LegacyRulesCliError::Input(format!(
                "packages list exceeds {MAX_PACKAGE_LIST_LINES} lines"
            )));
        }
        if line.len() > MAX_PACKAGE_LIST_LINE_BYTES
            || line
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(LegacyRulesCliError::Input(format!(
                "packages list line {} exceeds its bound or contains a control character",
                index + 1
            )));
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let package = fields.next().expect("nonempty line has a first field");
        let Some(uid) = fields.next() else {
            return Err(LegacyRulesCliError::Input(format!(
                "packages list line {} has no UID field",
                index + 1
            )));
        };
        validate_package_name(package).map_err(|reason| {
            LegacyRulesCliError::Input(format!("packages list line {} {reason}", index + 1))
        })?;
        let uid = parse_decimal::<u32>("packages.list UID", uid)?;
        if !targets.contains(package) {
            continue;
        }
        let app_id = uid % ANDROID_UID_STRIDE;
        let next_len = ordered.len().checked_add(users.len()).ok_or_else(|| {
            LegacyRulesCliError::Input(
                "resolved application UID count overflowed its bound".to_owned(),
            )
        })?;
        if next_len > MAX_LEGACY_APPLICATION_UIDS {
            return Err(LegacyRulesCliError::Input(format!(
                "resolved application UID count exceeds {MAX_LEGACY_APPLICATION_UIDS}"
            )));
        }
        ordered.try_reserve(users.len()).map_err(|_| {
            LegacyRulesCliError::Input(
                "cannot reserve bounded resolved application UID storage".to_owned(),
            )
        })?;
        for user in users {
            let derived = u32::from(*user)
                .checked_mul(ANDROID_UID_STRIDE)
                .and_then(|base| base.checked_add(app_id))
                .ok_or_else(|| {
                    LegacyRulesCliError::Input("derived Android UID overflowed u32".to_owned())
                })?;
            ordered.push(derived);
        }
    }
    Ok(ordered)
}

fn validate_package_name(package: &str) -> Result<(), &'static str> {
    if package.is_empty()
        || package.len() > MAX_PACKAGE_NAME_BYTES
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err("contains an invalid package name")
    } else {
        Ok(())
    }
}

fn invalid_environment(name: &'static str, reason: &str) -> LegacyRulesCliError {
    LegacyRulesCliError::Input(format!("environment {name} {reason}"))
}

enum LegacyRulesCliError {
    Usage(String),
    Unsupported(String),
    Input(String),
}
