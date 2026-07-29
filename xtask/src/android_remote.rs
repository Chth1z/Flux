use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::process::Output;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OwnedRemoteDirectorySpec {
    prefix: &'static str,
    token_bytes: usize,
    owner_file: &'static str,
    owner_domain: &'static str,
}

impl OwnedRemoteDirectorySpec {
    pub(super) const fn new(
        prefix: &'static str,
        token_bytes: usize,
        owner_file: &'static str,
        owner_domain: &'static str,
    ) -> Self {
        Self {
            prefix,
            token_bytes,
            owner_file,
            owner_domain,
        }
    }

    pub(super) fn generate(self, description: &str) -> Result<OwnedRemoteDirectory, String> {
        self.validate(description)?;
        let mut bytes = vec![0_u8; self.token_bytes];
        fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut bytes))
            .map_err(|error| format!("generate {description} token: {error}"))?;
        self.directory_for_token(&encode_lower_hex(&bytes), description)
    }

    pub(super) fn directory_for_token(
        self,
        token: &str,
        description: &str,
    ) -> Result<OwnedRemoteDirectory, String> {
        self.validate(description)?;
        let expected_length = self
            .token_bytes
            .checked_mul(2)
            .ok_or_else(|| format!("{description} token length overflows"))?;
        if token.len() != expected_length
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "{description} token is not canonical lower-case hex"
            ));
        }
        Ok(OwnedRemoteDirectory {
            spec: self,
            path: format!("{}{token}", self.prefix),
            token: token.to_owned(),
            identity: None,
        })
    }

    pub(super) fn matches_path(self, path: &str) -> bool {
        path.strip_prefix(self.prefix).is_some_and(|suffix| {
            suffix.len() == self.token_bytes.saturating_mul(2)
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }

    fn validate(self, description: &str) -> Result<(), String> {
        if self.token_bytes < 16 || self.token_bytes > 64 {
            return Err(format!(
                "{description} token size must be between 16 and 64 bytes"
            ));
        }
        if !self.prefix.starts_with("/data/local/tmp/")
            || !self.prefix.ends_with('.')
            || !safe_literal(self.prefix.as_bytes(), b"/._-")
        {
            return Err(format!(
                "{description} prefix is outside the canonical /data/local/tmp namespace"
            ));
        }
        if self.owner_file.is_empty()
            || self.owner_file.contains('/')
            || !safe_literal(self.owner_file.as_bytes(), b"._-")
        {
            return Err(format!("{description} owner filename is not canonical"));
        }
        if self.owner_domain.is_empty() || !safe_literal(self.owner_domain.as_bytes(), b"._-") {
            return Err(format!("{description} owner domain is not canonical"));
        }
        Ok(())
    }
}

fn safe_literal(bytes: &[u8], punctuation: &[u8]) -> bool {
    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || punctuation.iter().any(|allowed| byte == allowed)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FilesystemIdentity {
    device: u64,
    inode: u64,
}

impl FilesystemIdentity {
    pub(super) fn new(device: u64, inode: u64) -> Result<Self, String> {
        if inode == 0 {
            return Err("remote directory identity has a zero inode".to_owned());
        }
        Ok(Self { device, inode })
    }

    fn render(self) -> String {
        format!("{}:{}", self.device, self.inode)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnedRemoteDirectory {
    spec: OwnedRemoteDirectorySpec,
    path: String,
    token: String,
    identity: Option<FilesystemIdentity>,
}

impl OwnedRemoteDirectory {
    pub(super) fn path(&self) -> &str {
        &self.path
    }

    #[cfg(test)]
    pub(super) fn token(&self) -> &str {
        &self.token
    }

    pub(super) const fn identity(&self) -> Option<FilesystemIdentity> {
        self.identity
    }

    pub(super) fn bind_identity(&mut self, identity: FilesystemIdentity) -> Result<(), String> {
        if self.identity.is_some() {
            return Err("remote directory identity was already bound".to_owned());
        }
        self.identity = Some(identity);
        Ok(())
    }

    pub(super) fn owner_record(&self) -> String {
        format!("{}:{}", self.spec.owner_domain, self.token)
    }

    pub(super) fn shell_variables(&self, shell_uid: u32, shell_gid: u32) -> String {
        let root = shell_single_quote(&self.path);
        let owner_record = shell_single_quote(&self.owner_record());
        let expected_identity = shell_single_quote(
            &self
                .identity
                .map(FilesystemIdentity::render)
                .unwrap_or_default(),
        );
        let owner_file = self.spec.owner_file;
        format!(
            "ROOT={root}\n\
             OWNER=\"$ROOT/{owner_file}\"\n\
             EXPECTED_OWNER_RECORD={owner_record}\n\
             EXPECTED_DIRECTORY_ID={expected_identity}\n\
             EXPECTED_SHELL_OWNER='700:{shell_uid}:{shell_gid}'\n"
        )
    }

    pub(super) fn matches_spec(&self) -> bool {
        self.spec.matches_path(&self.path)
    }
}

pub(super) fn run_owned_remote_transaction<Create, Execute, Cleanup>(
    remote: &mut OwnedRemoteDirectory,
    create: Create,
    execute: Execute,
    cleanup: Cleanup,
) -> Result<(), String>
where
    Create: FnOnce(&OwnedRemoteDirectory) -> Result<FilesystemIdentity, String>,
    Execute: FnOnce(&OwnedRemoteDirectory) -> Result<(), String>,
    Cleanup: FnOnce(&OwnedRemoteDirectory) -> Result<(), String>,
{
    let execution = match create(remote) {
        Ok(identity) => remote
            .bind_identity(identity)
            .and_then(|()| execute(remote)),
        Err(error) => Err(error),
    };
    combine_execution_and_cleanup(execution, cleanup(remote))
}

fn combine_execution_and_cleanup(
    execution: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (execution, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; mandatory remote cleanup also failed: {cleanup_error}"
        )),
    }
}

pub(super) fn parse_directory_identity(
    bytes: &[u8],
    begin: &str,
    end: &str,
    field: &str,
    description: &str,
) -> Result<FilesystemIdentity, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| format!("{description} identity is not UTF-8"))?;
    let lines = text.trim_end_matches('\n').split('\n').collect::<Vec<_>>();
    let [actual_begin, identity, actual_end] = lines.as_slice() else {
        return Err(format!("{description} identity has an invalid line count"));
    };
    if *actual_begin != begin || *actual_end != end {
        return Err(format!("{description} identity has an invalid schema"));
    }
    parse_filesystem_identity_field(identity, field)
}

fn parse_filesystem_identity_field(line: &str, key: &str) -> Result<FilesystemIdentity, String> {
    let value = line
        .strip_prefix(key)
        .and_then(|suffix| suffix.strip_prefix('='))
        .ok_or_else(|| format!("{key} is missing"))?;
    let (device, inode) = value
        .split_once(':')
        .ok_or_else(|| format!("{key} is malformed"))?;
    FilesystemIdentity::new(
        parse_canonical_u64(device, key)?,
        parse_canonical_u64(inode, key)?,
    )
}

fn parse_canonical_u64(value: &str, field: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} is not a canonical unsigned decimal"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} exceeds the u64 domain"))
}

pub(super) const fn path_absence_function() -> &'static str {
    "path_absent() {\n\
       [ ! -e \"$1\" ] && [ ! -L \"$1\" ]\n\
     }\n"
}

pub(super) fn owned_root_functions() -> String {
    let mut functions = String::from(path_absence_function());
    functions.push_str(
        "owned_root_matches() {\n\
       [ -d \"$ROOT\" ] && [ ! -L \"$ROOT\" ] || return 1\n\
       CURRENT_DIRECTORY_ID=$(/system/bin/stat -Lc '%d:%i' \"$ROOT\") || return 1\n\
       [ -z \"$EXPECTED_DIRECTORY_ID\" ] || [ \"$CURRENT_DIRECTORY_ID\" = \"$EXPECTED_DIRECTORY_ID\" ] || return 1\n\
       ROOT_OWNER=$(/system/bin/stat -c '%a:%u:%g' \"$ROOT\") || return 1\n\
       [ \"$ROOT_OWNER\" = '700:0:0' ] || [ \"$ROOT_OWNER\" = \"$EXPECTED_SHELL_OWNER\" ] || return 1\n\
       [ -f \"$OWNER\" ] && [ ! -L \"$OWNER\" ] || return 1\n\
       [ \"$(/system/bin/stat -c '%a:%u:%g' \"$OWNER\")\" = '600:0:0' ] || return 1\n\
       [ \"$(/system/bin/cat \"$OWNER\")\" = \"$EXPECTED_OWNER_RECORD\" ]\n\
     }\n\
     remove_owned_root() {\n\
       identity_matches || return 70\n\
       probe_process_absent\n\
       if path_absent \"$ROOT\"; then return 0; fi\n\
       owned_root_matches || return 73\n\
       /system/bin/rm -rf \"$ROOT\"\n\
       path_absent \"$ROOT\"\n\
     }\n",
    );
    functions
}

pub(super) fn process_absence_function(process_names: &[&str]) -> String {
    assert!(
        !process_names.is_empty(),
        "process-name set must not be empty"
    );
    let mut unique = BTreeSet::new();
    for process_name in process_names {
        assert!(
            (1..=15).contains(&process_name.len()) && safe_literal(process_name.as_bytes(), b"._-"),
            "process name must fit Linux comm and use canonical ASCII"
        );
        assert!(
            unique.insert(*process_name),
            "process-name set must not contain duplicates"
        );
    }
    let expected_process_names = process_names
        .iter()
        .map(|name| shell_single_quote(name))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "probe_process_absent() {{\n\
           for COMM in /proc/[0-9]*/comm; do\n\
             [ -e \"$COMM\" ] || continue\n\
             if ! NAME=$(/system/bin/cat \"$COMM\"); then\n\
               [ ! -e \"$COMM\" ] && continue\n\
               return 71\n\
             fi\n\
             for EXPECTED_PROCESS_NAME in {expected_process_names}; do\n\
               [ \"$NAME\" != \"$EXPECTED_PROCESS_NAME\" ] || return 72\n\
             done\n\
           done\n\
         }}\n"
    )
}

pub(super) fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn normalize_adb_shell_output(mut output: Output) -> Result<Output, String> {
    output.stdout = normalize_adb_shell_newlines(output.stdout, "stdout")?;
    output.stderr = normalize_adb_shell_newlines(output.stderr, "stderr")?;
    Ok(output)
}

pub(super) fn normalize_adb_shell_newlines(
    bytes: Vec<u8>,
    stream: &str,
) -> Result<Vec<u8>, String> {
    if !bytes.contains(&b'\r') {
        return Ok(bytes);
    }

    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => {
                normalized.push(b'\n');
                index += 2;
            }
            b'\r' => {
                return Err(format!(
                    "ADB shell {stream} contains a bare carriage return"
                ));
            }
            b'\n' => {
                return Err(format!("ADB shell {stream} mixes LF and CRLF line endings"));
            }
            byte => {
                normalized.push(byte);
                index += 1;
            }
        }
    }
    Ok(normalized)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const SPEC: OwnedRemoteDirectorySpec = OwnedRemoteDirectorySpec::new(
        "/data/local/tmp/flux-test.",
        32,
        ".flux-test-owner",
        "flux-android-test-owner-v1",
    );

    #[test]
    fn directory_identity_is_random_owner_marked_and_inode_bound() {
        let mut remote = SPEC
            .directory_for_token(&"a1".repeat(32), "test remote directory")
            .expect("canonical token");
        assert!(remote.matches_spec());
        assert_eq!(remote.token(), "a1".repeat(32));
        assert_eq!(
            remote.owner_record(),
            format!("flux-android-test-owner-v1:{}", "a1".repeat(32))
        );
        remote
            .bind_identity(FilesystemIdentity::new(7, 11).expect("identity"))
            .expect("bind identity");
        let variables = remote.shell_variables(2000, 2000);
        assert!(variables.contains("EXPECTED_DIRECTORY_ID='7:11'"));
        assert!(variables.contains("EXPECTED_SHELL_OWNER='700:2000:2000'"));
        assert!(
            remote
                .bind_identity(FilesystemIdentity::new(7, 12).expect("identity"))
                .is_err()
        );
        assert_eq!(
            remote.identity(),
            Some(FilesystemIdentity::new(7, 11).expect("identity"))
        );
    }

    #[test]
    fn token_and_identity_grammars_fail_closed() {
        assert!(SPEC.directory_for_token(&"a1".repeat(32), "test").is_ok());
        assert!(SPEC.directory_for_token(&"A1".repeat(32), "test").is_err());
        assert!(SPEC.directory_for_token("a1", "test").is_err());
        assert!(SPEC.matches_path(&format!("/data/local/tmp/flux-test.{}", "00".repeat(32))));
        assert!(!SPEC.matches_path(&format!(
            "/data/local/tmp/flux-test.{}/child",
            "00".repeat(32)
        )));

        let report = b"BEGIN\ndirectory_identity=253:91337\nEND\n";
        assert_eq!(
            parse_directory_identity(report, "BEGIN", "END", "directory_identity", "test")
                .expect("identity"),
            FilesystemIdentity::new(253, 91_337).expect("identity")
        );
        for malformed in [
            b"BEGIN\ndirectory_identity=253:0\nEND\n".as_slice(),
            b"BEGIN\ndirectory_identity=0253:1\nEND\n".as_slice(),
            b"BEGIN\ndirectory_identity=253:1\nEXTRA\nEND\n".as_slice(),
        ] {
            assert!(
                parse_directory_identity(malformed, "BEGIN", "END", "directory_identity", "test")
                    .is_err()
            );
        }
    }

    #[test]
    fn shell_output_accepts_uniform_lf_or_crlf_only() {
        assert_eq!(
            normalize_adb_shell_newlines(b"one\ntwo\n".to_vec(), "stdout").expect("LF"),
            b"one\ntwo\n"
        );
        assert_eq!(
            normalize_adb_shell_newlines(b"one\r\ntwo\r\n".to_vec(), "stdout").expect("CRLF"),
            b"one\ntwo\n"
        );
        assert!(normalize_adb_shell_newlines(b"one\rbare".to_vec(), "stdout").is_err());
        assert!(normalize_adb_shell_newlines(b"one\r\ntwo\n".to_vec(), "stdout").is_err());
    }

    #[test]
    fn process_absence_scan_distinguishes_read_failure_from_process_residue() {
        let function = process_absence_function(&["fluxd-test", "flux-cred-probe"]);
        assert!(function.contains("for COMM in /proc/[0-9]*/comm"));
        assert!(function.contains("for EXPECTED_PROCESS_NAME in 'fluxd-test' 'flux-cred-probe'"));
        assert!(function.contains("return 71"));
        assert!(function.contains("return 72"));
        assert!(function.contains("[ ! -e \"$COMM\" ] && continue"));
        assert!(!function.contains("pidof"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shell_path_absence_rejects_a_dangling_symlink() {
        use std::os::unix::fs::symlink;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let fixture = std::env::temp_dir().join(format!(
            "flux-android-path-absence-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&fixture).expect("create strict path-absence fixture");
        let root = fixture.join("remote-root");
        let root_text = root.to_str().expect("ASCII test path");
        let script = format!("set -eu\n{}path_absent \"$1\"\n", path_absence_function());
        let run = |path: &str| {
            Command::new("/bin/sh")
                .args(["-c", &script, "flux-path-absence-test", path])
                .status()
                .expect("run strict path-absence shell predicate")
                .success()
        };

        let missing_is_absent = run(root_text);
        symlink("missing-target", &root).expect("create dangling remote-root symlink");
        let dangling_is_absent = run(root_text);
        std::fs::remove_file(&root).expect("remove dangling remote-root symlink");
        std::fs::remove_dir(&fixture).expect("remove strict path-absence fixture");

        assert!(missing_is_absent);
        assert!(!dangling_is_absent);
    }

    #[test]
    fn transaction_always_attempts_cleanup_after_ambiguous_creation() {
        let events = RefCell::new(Vec::new());
        let mut remote = SPEC
            .directory_for_token(&"b2".repeat(32), "test")
            .expect("remote");
        let error = run_owned_remote_transaction(
            &mut remote,
            |_| {
                events.borrow_mut().push("create");
                Err("creation response lost".to_owned())
            },
            |_| panic!("execution must not follow uncertain creation"),
            |remote| {
                events.borrow_mut().push("cleanup");
                assert_eq!(remote.identity(), None);
                Ok(())
            },
        )
        .expect_err("ambiguous creation must fail");
        assert_eq!(error, "creation response lost");
        assert_eq!(*events.borrow(), ["create", "cleanup"]);
    }
}
