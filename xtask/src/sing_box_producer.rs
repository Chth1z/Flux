use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::Deserialize;

use crate::hash::sha256_file;

pub(super) const COMMAND: &str = "build-sing-box-producer";
const MANIFEST_RELATIVE: &str = "engine/sing-box/manifest.toml";
const EXPECTED_SCHEMA: u32 = 1;
const EXPECTED_PROTOCOL: &str = "flux-supervised-delivery-report-schema-v1-handoff-v1";
const REQUIRED_BUILD_TAG: &str = "with_flux_report";
const LAUNCH_CONTROL_ENV: &str = "FLUX_SING_BOX_LAUNCH_CONTROL_FD";
const REAL_PRODUCER_BINARY_ENV: &str = "FLUX_TEST_SING_BOX_PRODUCER_BINARY";
const REAL_PRODUCER_COMPOSITION_TEST: &str = "functional_canary::supervised_delivery_report::tests::real_sing_box_producer_obeys_exact_attempt_ownership";

#[derive(Debug, Eq, PartialEq)]
struct Options {
    source: PathBuf,
    go_sdk: PathBuf,
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    producer_protocol: String,
    upstream: Upstream,
    patches: Vec<Patch>,
    patched_source: PatchedSource,
    toolchain: Toolchain,
    build: Build,
    artifact: Artifact,
    license: License,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    repository: String,
    tag: String,
    commit: String,
    tree: String,
    go_directive: String,
    go_mod_sha256: String,
    default_build_tags_sha256: String,
    upstream_ldflags_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchedSource {
    tree: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Toolchain {
    version: String,
    download_url: String,
    archive_sha256: String,
    archive_bytes: u64,
    executable_sha256: String,
    executable_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Build {
    target_os: String,
    target_arch: String,
    target_variant: String,
    cgo_enabled: bool,
    tags: String,
    version: String,
    trimpath: bool,
    build_vcs: bool,
    module_mode: String,
    ldflags: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct License {
    spdx: String,
    base_spdx: String,
    file: String,
    sha256: String,
    notice: String,
}

pub(super) fn run(arguments: &[OsString]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    let workspace = workspace_root()?;
    let manifest_path = workspace.join(MANIFEST_RELATIVE);
    let manifest_directory = manifest_path
        .parent()
        .expect("the checked manifest has a parent");
    let manifest = read_manifest(&manifest_path)?;
    validate_manifest(&manifest, manifest_directory)?;

    let source = canonical_directory(&options.source, "Sing-Box source")?;
    let go_sdk = canonical_file(&options.go_sdk, "Go SDK archive")?;
    let output = validate_output_path(&options.output)?;
    validate_upstream(&source, &manifest)?;

    let temporary = TemporaryDirectory::new("sing-box-producer")?;
    let go = prepare_go_toolchain(&go_sdk, temporary.path(), &manifest.toolchain)?;
    let patched = temporary.path().join("source");
    run_status(
        Command::new("git")
            .args(["clone", "--quiet", "--no-checkout", "--no-hardlinks"])
            .arg(&source)
            .arg(&patched),
        "clone pinned Sing-Box source",
    )?;
    run_status(
        Command::new("git")
            .arg("-C")
            .arg(&patched)
            .args(["checkout", "--quiet", "--detach"])
            .arg(&manifest.upstream.commit),
        "checkout pinned Sing-Box commit",
    )?;
    apply_patches(&patched, manifest_directory, &manifest.patches)?;
    let patched_tree = git_stdout(&patched, ["write-tree"])?;
    require_equal(
        "post-apply source tree",
        patched_tree.trim(),
        &manifest.patched_source.tree,
    )?;

    let module_cache = temporary.path().join("go-module-cache");
    let test_cache = temporary.path().join("go-test-cache");
    run_go_tests(&go, &patched, &manifest.build, &test_cache, &module_cache)?;
    remove_task_directory(&test_cache, "producer test build cache")?;
    let first = temporary.path().join("build-a/sing-box");
    let second = temporary.path().join("build-b/sing-box");
    fs::create_dir_all(first.parent().expect("first build has a parent"))
        .map_err(|error| format!("create first build directory: {error}"))?;
    fs::create_dir_all(second.parent().expect("second build has a parent"))
        .map_err(|error| format!("create second build directory: {error}"))?;
    let first_cache = temporary.path().join("go-cache-a");
    build_once(
        &go,
        &patched,
        &manifest.build,
        &first,
        &first_cache,
        &module_cache,
    )?;
    remove_task_directory(&first_cache, "first producer build cache")?;
    let second_cache = temporary.path().join("go-cache-b");
    build_once(
        &go,
        &patched,
        &manifest.build,
        &second,
        &second_cache,
        &module_cache,
    )?;
    remove_task_directory(&second_cache, "second producer build cache")?;
    require_identical_files(&first, &second)?;
    let expected_artifact = ArtifactEvidence {
        sha256: manifest.artifact.sha256.clone(),
        bytes: manifest.artifact.bytes,
    };
    require_artifact_evidence(&artifact_evidence(&first)?, &expected_artifact)?;
    verify_probe_isolation(
        &first,
        temporary.path(),
        &manifest.build,
        &manifest.toolchain.version,
    )?;
    verify_rust_composition(&workspace, &first)?;

    let artifact = publish_artifact_atomically(&first, &output, &expected_artifact)?;
    println!("sing_box_upstream_commit={}", manifest.upstream.commit);
    println!("sing_box_patched_tree={}", manifest.patched_source.tree);
    println!("sing_box_producer_sha256={}", artifact.sha256);
    println!("sing_box_producer_bytes={}", artifact.bytes);
    println!("sing_box_producer_output={}", output.display());
    Ok(())
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut source = None;
    let mut go_sdk = None;
    let mut output = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "producer build arguments must be UTF-8".to_owned())?;
        index += 1;
        let value = arguments
            .get(index)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        index += 1;
        match flag {
            "--source" if source.replace(PathBuf::from(value)).is_none() => {}
            "--go-sdk" if go_sdk.replace(PathBuf::from(value)).is_none() => {}
            "--output" if output.replace(PathBuf::from(value)).is_none() => {}
            "--source" | "--go-sdk" | "--output" => {
                return Err(format!("duplicate option {flag}"));
            }
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(Options {
        source: source.ok_or_else(|| "missing required --source DIR".to_owned())?,
        go_sdk: go_sdk.ok_or_else(|| "missing required --go-sdk FILE".to_owned())?,
        output: output.ok_or_else(|| "missing required --output FILE".to_owned())?,
    })
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("read producer manifest {}: {error}", path.display()))?;
    toml::from_str(&source)
        .map_err(|error| format!("parse producer manifest {}: {error}", path.display()))
}

fn validate_manifest(manifest: &Manifest, directory: &Path) -> Result<(), String> {
    if manifest.schema_version != EXPECTED_SCHEMA
        || manifest.producer_protocol != EXPECTED_PROTOCOL
        || manifest.patches.len() != 1
    {
        return Err(
            "producer manifest schema, protocol, or patch cardinality is invalid".to_owned(),
        );
    }
    require_https_repository(&manifest.upstream.repository)?;
    require_lower_hex("upstream commit", &manifest.upstream.commit, 40)?;
    require_lower_hex("upstream tree", &manifest.upstream.tree, 40)?;
    require_lower_hex("patched tree", &manifest.patched_source.tree, 40)?;
    for (field, digest) in [
        ("go.mod digest", &manifest.upstream.go_mod_sha256),
        (
            "default build tags digest",
            &manifest.upstream.default_build_tags_sha256,
        ),
        (
            "upstream ldflags digest",
            &manifest.upstream.upstream_ldflags_sha256,
        ),
        ("license digest", &manifest.license.sha256),
        ("artifact digest", &manifest.artifact.sha256),
        ("Go SDK archive digest", &manifest.toolchain.archive_sha256),
        (
            "Go SDK executable digest",
            &manifest.toolchain.executable_sha256,
        ),
    ] {
        require_lower_hex(field, digest, 64)?;
    }
    if manifest.upstream.tag != "v1.13.14"
        || manifest.upstream.go_directive != "1.24.7"
        || manifest.toolchain.version != "go1.24.7"
        || manifest.toolchain.download_url != "https://go.dev/dl/go1.24.7.linux-amd64.tar.gz"
        || manifest.toolchain.archive_bytes == 0
        || manifest.toolchain.executable_bytes == 0
        || manifest.build.target_os != "linux"
        || manifest.build.target_arch != "amd64"
        || manifest.build.target_variant != "v1"
        || manifest.build.cgo_enabled
        || !manifest.build.trimpath
        || manifest.build.build_vcs
        || manifest.build.module_mode != "readonly"
        || manifest.build.version != "1.13.14-flux.1"
        || manifest.license.spdx != "LicenseRef-Sing-Box-GPL-3.0-or-later-with-Additional-Terms"
        || manifest.license.base_spdx != "GPL-3.0-or-later"
        || manifest.license.file != "LICENSE"
        || manifest.artifact.bytes == 0
    {
        return Err(
            "producer manifest weakens a pinned source, build, or license invariant".to_owned(),
        );
    }
    let tags = manifest.build.tags.split(',').collect::<Vec<_>>();
    if tags.iter().any(|tag| {
        tag.is_empty()
            || !tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }) || tags
        .iter()
        .filter(|tag| **tag == REQUIRED_BUILD_TAG)
        .count()
        != 1
        || tags.iter().copied().collect::<BTreeSet<_>>().len() != tags.len()
    {
        return Err("producer build tags are not canonical and unique".to_owned());
    }
    if manifest.build.ldflags
        != "-X github.com/sagernet/sing-box/constant.Version=1.13.14-flux.1 -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0 -s -w -buildid="
    {
        return Err("producer linker flags are not canonical".to_owned());
    }
    for patch in &manifest.patches {
        validate_relative_path("patch", &patch.path)?;
        require_lower_hex("patch digest", &patch.sha256, 64)?;
        let path = directory.join(&patch.path);
        require_equal("patch digest", &sha256_file(&path)?, &patch.sha256)?;
    }
    Ok(())
}

fn validate_upstream(source: &Path, manifest: &Manifest) -> Result<(), String> {
    require_equal(
        "upstream commit",
        git_stdout(source, ["rev-parse", "HEAD"])?.trim(),
        &manifest.upstream.commit,
    )?;
    require_equal(
        "upstream tree",
        git_stdout(source, ["rev-parse", "HEAD^{tree}"])?.trim(),
        &manifest.upstream.tree,
    )?;
    let tag_reference = format!("refs/tags/{}^{{commit}}", manifest.upstream.tag);
    require_equal(
        "upstream tag target",
        git_stdout(source, ["rev-parse", &tag_reference])?.trim(),
        &manifest.upstream.commit,
    )?;
    let status = git_stdout(
        source,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err("Sing-Box source checkout must be clean, including untracked files".to_owned());
    }
    let origin = git_stdout(source, ["remote", "get-url", "origin"])?;
    let expected = manifest.upstream.repository.trim_end_matches(".git");
    if origin.trim().trim_end_matches(".git") != expected {
        return Err(format!(
            "upstream origin is {}, expected {}",
            origin.trim(),
            manifest.upstream.repository
        ));
    }
    require_equal(
        "go.mod digest",
        &sha256_file(&source.join("go.mod"))?,
        &manifest.upstream.go_mod_sha256,
    )?;
    require_equal(
        "default build tags digest",
        &sha256_file(&source.join("release/DEFAULT_BUILD_TAGS_OTHERS"))?,
        &manifest.upstream.default_build_tags_sha256,
    )?;
    require_equal(
        "upstream ldflags digest",
        &sha256_file(&source.join("release/LDFLAGS"))?,
        &manifest.upstream.upstream_ldflags_sha256,
    )?;
    let license_path = source.join(&manifest.license.file);
    require_equal(
        "license digest",
        &sha256_file(&license_path)?,
        &manifest.license.sha256,
    )?;
    let license = fs::read_to_string(&license_path)
        .map_err(|error| format!("read upstream license {}: {error}", license_path.display()))?;
    if !license.contains("no derivative work may use the name or imply association")
        || manifest.license.notice.trim().is_empty()
    {
        return Err("upstream naming restriction is absent from license provenance".to_owned());
    }
    let go_mod = fs::read_to_string(source.join("go.mod"))
        .map_err(|error| format!("read upstream go.mod: {error}"))?;
    if !go_mod
        .lines()
        .any(|line| line == format!("go {}", manifest.upstream.go_directive))
    {
        return Err("upstream go directive does not match the manifest".to_owned());
    }
    let upstream_tags = fs::read_to_string(source.join("release/DEFAULT_BUILD_TAGS_OTHERS"))
        .map_err(|error| format!("read upstream default build tags: {error}"))?;
    let expected_tags = format!("{},{}", upstream_tags.trim(), REQUIRED_BUILD_TAG);
    require_equal("producer build tags", &manifest.build.tags, &expected_tags)
}

fn apply_patches(source: &Path, directory: &Path, patches: &[Patch]) -> Result<(), String> {
    for patch in patches {
        let path = directory.join(&patch.path);
        run_status(
            Command::new("git")
                .arg("-C")
                .arg(source)
                .args(["apply", "--check", "--whitespace=error-all"])
                .arg(&path),
            "check Sing-Box producer patch",
        )?;
        run_status(
            Command::new("git")
                .arg("-C")
                .arg(source)
                .args(["apply", "--index", "--whitespace=error-all"])
                .arg(&path),
            "apply Sing-Box producer patch",
        )?;
    }
    Ok(())
}

fn run_go_tests(
    go: &GoToolchain,
    source: &Path,
    build: &Build,
    build_cache: &Path,
    module_cache: &Path,
) -> Result<(), String> {
    create_go_cache(build_cache, "test build")?;
    create_go_cache(module_cache, "module")?;
    let mut command = go_command(go, source, build, module_cache);
    command.env("GOCACHE", build_cache);
    command.args([
        "test",
        "-mod=readonly",
        "-tags",
        &build.tags,
        "./internal/fluxreport",
        "./cmd/sing-box",
        "./common/listener",
        "./protocol/redirect",
    ]);
    run_status(&mut command, "test patched Sing-Box producer")
}

fn build_once(
    go: &GoToolchain,
    source: &Path,
    build: &Build,
    output: &Path,
    cache: &Path,
    module_cache: &Path,
) -> Result<(), String> {
    create_go_cache(cache, "build")?;
    let mut command = go_command(go, source, build, module_cache);
    command.env("GOCACHE", cache).args([
        "build",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=false",
        "-tags",
        &build.tags,
        "-ldflags",
        &build.ldflags,
        "-o",
    ]);
    command.arg(output).arg("./cmd/sing-box");
    run_status(&mut command, "build patched Sing-Box producer")
}

fn create_go_cache(path: &Path, kind: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "create isolated Go {kind} cache {}: {error}",
            path.display()
        )
    })
}

fn go_command(go: &GoToolchain, source: &Path, build: &Build, module_cache: &Path) -> Command {
    let mut command = Command::new(&go.executable);
    command
        .current_dir(source)
        .env("GOTOOLCHAIN", "local")
        .env("GOROOT", &go.root)
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env("GOTELEMETRY", "off")
        .env("GOMODCACHE", module_cache)
        .env("GOOS", &build.target_os)
        .env("GOARCH", &build.target_arch)
        .env("GOAMD64", &build.target_variant)
        .env_remove("GOFLAGS")
        .env_remove("GOEXPERIMENT")
        .env_remove("GOFIPS140")
        .env("CGO_ENABLED", if build.cgo_enabled { "1" } else { "0" });
    command
}

fn verify_probe_isolation(
    binary: &Path,
    directory: &Path,
    build: &Build,
    go_version: &str,
) -> Result<(), String> {
    let version = run_output(
        Command::new(binary)
            .arg("version")
            .env(LAUNCH_CONTROL_ENV, "not-a-descriptor"),
        "probe producer version",
    )?;
    let stdout = String::from_utf8(version.stdout)
        .map_err(|error| format!("producer version output is not UTF-8: {error}"))?;
    for required in [
        format!("sing-box version {}", build.version),
        format!(
            "Environment: {} {}/{}",
            go_version, build.target_os, build.target_arch
        ),
        format!("Tags: {}", build.tags),
        "CGO: disabled".to_owned(),
    ] {
        if !stdout.lines().any(|line| line == required) {
            return Err(format!("producer version output omits {required:?}"));
        }
    }
    let config = directory.join("probe-config.json");
    fs::write(&config, b"{\"log\":{\"disabled\":true}}\n")
        .map_err(|error| format!("write producer check fixture: {error}"))?;
    run_status(
        Command::new(binary)
            .args([OsStr::new("check"), OsStr::new("-c")])
            .arg(&config)
            .env(LAUNCH_CONTROL_ENV, "not-a-descriptor"),
        "probe producer configuration",
    )
}

fn verify_rust_composition(workspace: &Path, binary: &Path) -> Result<(), String> {
    let mut command = Command::new("unshare");
    command
        .current_dir(workspace)
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg("cargo")
        .args([
            "test",
            "-p",
            "fluxd",
            "--features",
            "native-composition-test",
            "--lib",
            REAL_PRODUCER_COMPOSITION_TEST,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ])
        .env(REAL_PRODUCER_BINARY_ENV, binary);
    run_status(&mut command, "compose real producer through Rust handoff")
}

struct GoToolchain {
    root: PathBuf,
    executable: PathBuf,
}

fn prepare_go_toolchain(
    archive: &Path,
    directory: &Path,
    contract: &Toolchain,
) -> Result<GoToolchain, String> {
    require_artifact_evidence(
        &artifact_evidence(archive)?,
        &ArtifactEvidence {
            sha256: contract.archive_sha256.clone(),
            bytes: contract.archive_bytes,
        },
    )?;
    let extraction = directory.join("go-sdk");
    fs::create_dir(&extraction).map_err(|error| {
        format!(
            "create Go SDK extraction directory {}: {error}",
            extraction.display()
        )
    })?;
    run_status(
        Command::new("tar")
            .args([
                "--extract",
                "--gzip",
                "--no-same-owner",
                "--no-same-permissions",
                "--file",
            ])
            .arg(archive)
            .arg("--directory")
            .arg(&extraction),
        "extract pinned Go SDK archive",
    )?;
    let root = canonical_directory(&extraction.join("go"), "extracted Go SDK root")?;
    let executable = canonical_file(&root.join("bin/go"), "extracted Go executable")?;
    require_artifact_evidence(
        &artifact_evidence(&executable)?,
        &ArtifactEvidence {
            sha256: contract.executable_sha256.clone(),
            bytes: contract.executable_bytes,
        },
    )?;
    let toolchain = GoToolchain { root, executable };
    validate_go(&toolchain, &contract.version)?;
    Ok(toolchain)
}

fn validate_go(go: &GoToolchain, expected: &str) -> Result<(), String> {
    let output = run_output(
        Command::new(&go.executable)
            .arg("version")
            .env("GOTOOLCHAIN", "local")
            .env("GOROOT", &go.root),
        "inspect Go toolchain",
    )?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("Go version output is not UTF-8: {error}"))?;
    if stdout.split_whitespace().nth(2) != Some(expected) {
        return Err(format!(
            "Go toolchain is {}, expected {expected}",
            stdout.trim()
        ));
    }
    Ok(())
}

fn require_identical_files(first: &Path, second: &Path) -> Result<(), String> {
    let first_metadata =
        fs::metadata(first).map_err(|error| format!("inspect first producer build: {error}"))?;
    let second_metadata =
        fs::metadata(second).map_err(|error| format!("inspect second producer build: {error}"))?;
    if first_metadata.len() != second_metadata.len() {
        return Err("independent producer builds have different lengths".to_owned());
    }
    let first_digest = sha256_file(first)?;
    let second_digest = sha256_file(second)?;
    if first_digest != second_digest {
        return Err("independent producer builds have different SHA-256 digests".to_owned());
    }
    let mut left =
        File::open(first).map_err(|error| format!("open first producer build: {error}"))?;
    let mut right =
        File::open(second).map_err(|error| format!("open second producer build: {error}"))?;
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let left_length = left
            .read(&mut left_buffer)
            .map_err(|error| format!("read first producer build: {error}"))?;
        let right_length = right
            .read(&mut right_buffer)
            .map_err(|error| format!("read second producer build: {error}"))?;
        if left_length != right_length || left_buffer[..left_length] != right_buffer[..right_length]
        {
            return Err("independent producer builds differ byte-for-byte".to_owned());
        }
        if left_length == 0 {
            return Ok(());
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ArtifactEvidence {
    sha256: String,
    bytes: u64,
}

fn artifact_evidence(path: &Path) -> Result<ArtifactEvidence, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("inspect producer artifact {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "producer artifact {} is not a regular file",
            path.display()
        ));
    }
    Ok(ArtifactEvidence {
        sha256: sha256_file(path)?,
        bytes: metadata.len(),
    })
}

fn require_artifact_evidence(
    actual: &ArtifactEvidence,
    expected: &ArtifactEvidence,
) -> Result<(), String> {
    require_equal("producer artifact digest", &actual.sha256, &expected.sha256)?;
    if actual.bytes != expected.bytes {
        return Err(format!(
            "producer artifact length is {}, expected {}",
            actual.bytes, expected.bytes
        ));
    }
    Ok(())
}

fn publish_artifact_atomically(
    source: &Path,
    output: &Path,
    expected: &ArtifactEvidence,
) -> Result<ArtifactEvidence, String> {
    let source_metadata = fs::metadata(source)
        .map_err(|error| format!("inspect reproducible producer build: {error}"))?;
    if !source_metadata.is_file() {
        return Err("reproducible producer build is not a regular file".to_owned());
    }

    let mut staged = SiblingTemporaryFile::new(output)?;
    let mut input =
        File::open(source).map_err(|error| format!("open reproducible producer build: {error}"))?;
    std::io::copy(&mut input, staged.file_mut()).map_err(|error| {
        format!(
            "stage producer artifact beside {}: {error}",
            output.display()
        )
    })?;
    fs::set_permissions(staged.path(), source_metadata.permissions()).map_err(|error| {
        format!(
            "set staged producer permissions beside {}: {error}",
            output.display()
        )
    })?;
    staged.sync_all().map_err(|error| {
        format!(
            "synchronize staged producer artifact beside {}: {error}",
            output.display()
        )
    })?;

    let evidence = artifact_evidence(staged.path())?;
    require_artifact_evidence(&evidence, expected)?;
    fs::hard_link(staged.path(), output).map_err(|error| {
        format!(
            "atomically publish producer artifact {} without replacement: {error}",
            output.display()
        )
    })?;
    Ok(evidence)
}

fn validate_output_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.file_name().is_none() || path.exists() {
        return Err("--output must be an absent absolute file path".to_owned());
    }
    let parent = canonical_directory(
        path.parent().expect("an output file has a parent"),
        "producer output parent",
    )?;
    Ok(parent.join(path.file_name().expect("an output file has a name")))
}

fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("resolve {description} {}: {error}", path.display()))?;
    if !fs::metadata(&canonical)
        .map_err(|error| format!("inspect {description} {}: {error}", canonical.display()))?
        .is_dir()
    {
        return Err(format!(
            "{description} {} is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path, description: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("resolve {description} {}: {error}", path.display()))?;
    if !fs::metadata(&canonical)
        .map_err(|error| format!("inspect {description} {}: {error}", canonical.display()))?
        .is_file()
    {
        return Err(format!(
            "{description} {} is not a regular file",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest directory has no workspace parent".to_owned())
}

fn validate_relative_path(field: &str, value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{field} path {value:?} is not canonical and relative"
        ));
    }
    Ok(())
}

fn require_https_repository(value: &str) -> Result<(), String> {
    if !value.starts_with("https://")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || !value[8..].contains('/')
    {
        return Err("upstream repository must be one canonical HTTPS URL".to_owned());
    }
    Ok(())
}

fn require_lower_hex(field: &str, value: &str, length: usize) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "{field} must be a nonzero lowercase {length}-digit hexadecimal value"
        ));
    }
    Ok(())
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} is {actual:?}, expected {expected:?}"))
    }
}

fn git_stdout<const N: usize>(source: &Path, arguments: [&str; N]) -> Result<String, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(source).args(arguments);
    let output = run_output(&mut command, "inspect Sing-Box Git source")?;
    String::from_utf8(output.stdout)
        .map_err(|error| format!("Git source output is not UTF-8: {error}"))
}

fn run_output(command: &mut Command, description: &str) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|error| format!("failed to {description}: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "failed to {description}: {}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_status(command: &mut Command, description: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("failed to {description}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("failed to {description}: {status}"))
    }
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Result<Self, String> {
        let root = env::temp_dir();
        for attempt in 0_u32..128 {
            let path = root.join(format!(
                "flux-{label}-{}-{}-{attempt}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| format!("read system clock: {error}"))?
                    .as_nanos()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "create temporary producer directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("exhausted temporary producer directory names".to_owned())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = remove_directory_tree(&self.0);
    }
}

fn remove_task_directory(path: &Path, description: &str) -> Result<(), String> {
    remove_directory_tree(path)
        .map_err(|error| format!("remove {description} {}: {error}", path.display()))
}

fn remove_directory_tree(path: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            make_owner_writable_tree(path)?;
            fs::remove_dir_all(path)
        }
    }
}

fn make_owner_writable_tree(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    let mut permissions = metadata.permissions();
    #[cfg(unix)]
    permissions.set_mode(permissions.mode() | if metadata.is_dir() { 0o700 } else { 0o600 });
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            make_owner_writable_tree(&entry?.path())?;
        }
    }
    Ok(())
}

struct SiblingTemporaryFile {
    path: PathBuf,
    file: Option<File>,
}

impl SiblingTemporaryFile {
    fn new(output: &Path) -> Result<Self, String> {
        let parent = output
            .parent()
            .expect("the validated output path has a parent");
        let output_name = output
            .file_name()
            .expect("the validated output path has a file name");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("read system clock: {error}"))?
            .as_nanos();
        for attempt in 0_u32..128 {
            let mut name = OsString::from(".");
            name.push(output_name);
            name.push(format!(
                ".flux-stage-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            let path = parent.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "create staged producer artifact beside {}: {error}",
                        output.display()
                    ));
                }
            }
        }
        Err("exhausted staged producer artifact names".to_owned())
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("the staged artifact remains open while publishing")
    }

    fn sync_all(&self) -> std::io::Result<()> {
        self.file
            .as_ref()
            .expect("the staged artifact remains open while publishing")
            .sync_all()
    }
}

impl Drop for SiblingTemporaryFile {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_manifest_is_strict_and_self_consistent() {
        let root = workspace_root().expect("workspace root");
        let path = root.join(MANIFEST_RELATIVE);
        let manifest = read_manifest(&path).expect("checked manifest parses");
        validate_manifest(&manifest, path.parent().expect("manifest parent"))
            .expect("checked manifest validates");
    }

    #[test]
    fn options_require_each_distinct_named_path() {
        let parsed = parse_options(&[
            OsString::from("--source"),
            OsString::from("/source"),
            OsString::from("--go-sdk"),
            OsString::from("/go-sdk.tar.gz"),
            OsString::from("--output"),
            OsString::from("/output"),
        ])
        .expect("parse producer options");
        assert_eq!(parsed.source, PathBuf::from("/source"));
        assert!(parse_options(&[]).is_err());
        assert!(
            parse_options(&[
                OsString::from("--source"),
                OsString::from("a"),
                OsString::from("--source"),
                OsString::from("b"),
            ])
            .is_err()
        );
    }

    #[test]
    fn relative_patch_paths_and_lowercase_digests_are_canonical() {
        assert!(validate_relative_path("patch", "patches/0001.patch").is_ok());
        assert!(validate_relative_path("patch", "../escape.patch").is_err());
        assert!(validate_relative_path("patch", "/absolute.patch").is_err());
        assert!(require_lower_hex("digest", &"a".repeat(64), 64).is_ok());
        assert!(require_lower_hex("digest", &"A".repeat(64), 64).is_err());
        assert!(require_lower_hex("digest", &"0".repeat(64), 64).is_err());
    }

    #[test]
    fn artifact_publication_is_atomic_exact_and_never_replaces() {
        let directory = TemporaryDirectory::new("producer-publication-test")
            .expect("create publication test directory");
        let source = directory.path().join("source");
        let output = directory.path().join("output");
        fs::write(&source, b"producer artifact\n").expect("write producer fixture");

        let expected = artifact_evidence(&source).expect("inspect source evidence");
        let evidence = publish_artifact_atomically(&source, &output, &expected)
            .expect("publish producer artifact");
        assert_eq!(evidence.bytes, 18);
        assert_eq!(evidence.sha256, sha256_file(&source).expect("hash source"));
        assert_eq!(
            fs::read(&output).expect("read output"),
            b"producer artifact\n"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("list publication directory")
                .count(),
            2,
            "staged artifact must be removed"
        );

        fs::write(&source, b"replacement\n").expect("replace source fixture");
        let replacement = artifact_evidence(&source).expect("inspect replacement evidence");
        assert!(publish_artifact_atomically(&source, &output, &replacement).is_err());
        assert_eq!(
            fs::read(&output).expect("reread output"),
            b"producer artifact\n"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("relist publication directory")
                .count(),
            2,
            "failed publication must remove its staged artifact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn temporary_directory_removes_read_only_module_cache_descendants() {
        let directory = TemporaryDirectory::new("producer-read-only-cleanup-test")
            .expect("create cleanup test directory");
        let path = directory.path().to_path_buf();
        let nested = path.join("module@v1.0.0");
        fs::create_dir(&nested).expect("create read-only module directory");
        let source = nested.join("source.go");
        fs::write(&source, b"package fixture\n").expect("write read-only module file");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444))
            .expect("make module file read-only");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o555))
            .expect("make module directory read-only");

        drop(directory);

        assert!(!path.exists(), "temporary module cache must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_cache_removal_handles_read_only_descendants() {
        let directory = TemporaryDirectory::new("producer-intermediate-cache-test")
            .expect("create intermediate-cache fixture");
        let cache = directory.path().join("go-cache");
        let nested = cache.join("module@v1.0.0");
        fs::create_dir_all(&nested).expect("create read-only cache directory");
        let source = nested.join("source.go");
        fs::write(&source, b"package fixture\n").expect("write read-only cache file");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o444))
            .expect("make cache file read-only");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o555))
            .expect("make cache directory read-only");

        remove_task_directory(&cache, "fixture cache").expect("remove intermediate cache");

        assert!(!cache.exists(), "intermediate cache must be removed");
    }
}
