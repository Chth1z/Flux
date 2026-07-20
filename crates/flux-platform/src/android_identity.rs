use flux_core::{DeviceIdentity, Observation};

pub(super) fn observe_system_android_device_identity() -> Observation<DeviceIdentity> {
    #[cfg(target_os = "android")]
    return implementation::observe_system_android_device_identity();

    #[cfg(not(target_os = "android"))]
    Observation::Unavailable
}

#[cfg(any(target_os = "android", test))]
mod implementation {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Read;
    use std::path::{Component, Path, PathBuf};

    use flux_core::{
        AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, DeviceIdentity,
        KernelBuildIdentity, NetworkNamespaceIdentity, Observation, SecurityPatchLevel,
        SelinuxPolicyIdentity, Sha256Digest, ToolId, VendorBuildIdentity, VerifiedBootIdentity,
        VerifiedBootState,
    };
    use sha2::{Digest, Sha256};

    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    const MAX_ANDROID_PROPERTY_BYTES: usize = 1_024;
    const MAX_APEX_INFO_BYTES: usize = 64 * 1024;
    const MAX_IDENTITY_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
    const CONNECTIVITY_APEX_MODULE: &str = "com.android.tethering";
    const PROC_SELF_EXE: &str = "/proc/self/exe";

    const PRODUCT_BRAND_PROPERTY: &str = "ro.product.brand";
    const PRODUCT_NAME_PROPERTY: &str = "ro.product.name";
    const PRODUCT_DEVICE_PROPERTY: &str = "ro.product.device";
    const BUILD_FINGERPRINT_PROPERTY: &str = "ro.build.fingerprint";
    const VENDOR_BUILD_FINGERPRINT_PROPERTY: &str = "ro.vendor.build.fingerprint";
    const SECURITY_PATCH_PROPERTY: &str = "ro.build.version.security_patch";
    const VERIFIED_BOOT_STATE_PROPERTY: &str = "ro.boot.verifiedbootstate";
    const VBMETA_DEVICE_STATE_PROPERTY: &str = "ro.boot.vbmeta.device_state";
    const FLASH_LOCKED_PROPERTY: &str = "ro.boot.flash.locked";
    const VBMETA_HASH_ALGORITHM_PROPERTY: &str = "ro.boot.vbmeta.hash_alg";
    const VBMETA_DIGEST_PROPERTY: &str = "ro.boot.vbmeta.digest";

    const REQUIRED_PROPERTY_NAMES: [&str; 11] = [
        PRODUCT_BRAND_PROPERTY,
        PRODUCT_NAME_PROPERTY,
        PRODUCT_DEVICE_PROPERTY,
        BUILD_FINGERPRINT_PROPERTY,
        VENDOR_BUILD_FINGERPRINT_PROPERTY,
        SECURITY_PATCH_PROPERTY,
        VERIFIED_BOOT_STATE_PROPERTY,
        VBMETA_DEVICE_STATE_PROPERTY,
        FLASH_LOCKED_PROPERTY,
        VBMETA_HASH_ALGORITHM_PROPERTY,
        VBMETA_DIGEST_PROPERTY,
    ];

    #[cfg(target_os = "android")]
    pub(super) fn observe_system_android_device_identity() -> Observation<DeviceIdentity> {
        let paths = match AndroidDeviceIdentityPaths::system() {
            Ok(paths) => paths,
            Err(failure) => return failure.into_observation(),
        };
        collect_android_device_identity(
            &SystemAndroidPropertySource,
            &paths,
            observe_system_kernel_build,
        )
    }

    pub(super) trait AndroidPropertySource {
        fn read_property(&self, name: &str) -> Result<Option<Vec<u8>>, IdentityFactFailure>;
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) struct AndroidDeviceIdentityPaths {
        pub(super) selinux_policy: PathBuf,
        pub(super) netd: PathBuf,
        pub(super) apex_info: PathBuf,
        pub(super) network_namespace: PathBuf,
        pub(super) tools: Vec<(ToolId, IdentityArtifactSource)>,
        pub(super) allowed_apex_roots: Vec<PathBuf>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) enum IdentityArtifactSource {
        #[cfg(test)]
        NoFollow(PathBuf),
        RunningExecutable,
    }

    impl AndroidDeviceIdentityPaths {
        #[cfg(target_os = "android")]
        fn system() -> Result<Self, IdentityFactFailure> {
            let fluxd = ToolId::new("fluxd").map_err(|_| IdentityFactFailure::Malformed)?;
            Ok(Self {
                selinux_policy: PathBuf::from("/sys/fs/selinux/policy"),
                netd: PathBuf::from("/system/bin/netd"),
                apex_info: PathBuf::from("/apex/apex-info-list.xml"),
                network_namespace: PathBuf::from("/proc/self/ns/net"),
                tools: vec![(fluxd, IdentityArtifactSource::RunningExecutable)],
                allowed_apex_roots: [
                    "/system/apex",
                    "/system_ext/apex",
                    "/product/apex",
                    "/vendor/apex",
                    "/odm/apex",
                    "/data/apex/active",
                    "/data/apex/decompressed",
                ]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            })
        }
    }

    pub(super) fn collect_android_device_identity<P, K>(
        properties: &P,
        paths: &AndroidDeviceIdentityPaths,
        kernel_build: K,
    ) -> Observation<DeviceIdentity>
    where
        P: AndroidPropertySource,
        K: Fn() -> Result<KernelBuildIdentity, IdentityFactFailure>,
    {
        match try_collect_android_device_identity(properties, paths, kernel_build) {
            Ok(identity) => Observation::Verified(identity),
            Err(failure) => failure.into_observation(),
        }
    }

    fn try_collect_android_device_identity<P, K>(
        properties: &P,
        paths: &AndroidDeviceIdentityPaths,
        kernel_build: K,
    ) -> Result<DeviceIdentity, IdentityFactFailure>
    where
        P: AndroidPropertySource,
        K: Fn() -> Result<KernelBuildIdentity, IdentityFactFailure>,
    {
        let namespace_before = observe_network_namespace(&paths.network_namespace)?;
        let properties_before = observe_property_snapshot(properties)?;
        let parsed_properties = parse_property_snapshot(&properties_before)?;
        let kernel_before = kernel_build()?;
        let connectivity_path_before = observe_active_apex_path(paths)?;

        let selinux_policy =
            SelinuxPolicyIdentity::from(observe_nofollow_artifact(&paths.selinux_policy)?);
        let netd = observe_nofollow_artifact(&paths.netd)?;
        let connectivity = observe_nofollow_artifact(&connectivity_path_before)?;
        let mut tools = Vec::with_capacity(paths.tools.len());
        for (tool, source) in &paths.tools {
            tools.push((tool.clone(), observe_identity_artifact(source)?));
        }

        let connectivity_path_after = observe_active_apex_path(paths)?;
        let kernel_after = kernel_build()?;
        let properties_after = observe_property_snapshot(properties)?;
        let namespace_after = observe_network_namespace(&paths.network_namespace)?;
        if namespace_before != namespace_after
            || properties_before != properties_after
            || kernel_before != kernel_after
            || connectivity_path_before != connectivity_path_after
        {
            return Err(IdentityFactFailure::Malformed);
        }

        DeviceIdentity::new(
            parsed_properties.android_product,
            parsed_properties.android_build,
            parsed_properties.vendor_build,
            parsed_properties.security_patch,
            parsed_properties.verified_boot,
            kernel_before,
            selinux_policy,
            netd,
            connectivity,
            tools,
            namespace_before,
        )
        .map_err(|_| IdentityFactFailure::Malformed)
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct AndroidPropertySnapshot {
        values: BTreeMap<&'static str, Option<Vec<u8>>>,
    }

    fn observe_property_snapshot(
        source: &impl AndroidPropertySource,
    ) -> Result<AndroidPropertySnapshot, IdentityFactFailure> {
        let mut values = BTreeMap::new();
        for name in REQUIRED_PROPERTY_NAMES {
            let value = source.read_property(name)?;
            if value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_ANDROID_PROPERTY_BYTES)
            {
                return Err(IdentityFactFailure::Malformed);
            }
            values.insert(name, value);
        }
        Ok(AndroidPropertySnapshot { values })
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ParsedAndroidProperties {
        android_product: AndroidProductIdentity,
        android_build: AndroidBuildIdentity,
        vendor_build: VendorBuildIdentity,
        security_patch: SecurityPatchLevel,
        verified_boot: VerifiedBootIdentity,
    }

    fn parse_property_snapshot(
        snapshot: &AndroidPropertySnapshot,
    ) -> Result<ParsedAndroidProperties, IdentityFactFailure> {
        let product_brand = product_component(snapshot, PRODUCT_BRAND_PROPERTY)?;
        let product_name = product_component(snapshot, PRODUCT_NAME_PROPERTY)?;
        let product_device = product_component(snapshot, PRODUCT_DEVICE_PROPERTY)?;
        let android_product = AndroidProductIdentity::new(&format!(
            "{product_brand}/{product_name}/{product_device}"
        ))
        .map_err(|_| IdentityFactFailure::Malformed)?;
        let android_build =
            AndroidBuildIdentity::new(&build_fingerprint(snapshot, BUILD_FINGERPRINT_PROPERTY)?)
                .map_err(|_| IdentityFactFailure::Malformed)?;
        let vendor_build = VendorBuildIdentity::new(&build_fingerprint(
            snapshot,
            VENDOR_BUILD_FINGERPRINT_PROPERTY,
        )?)
        .map_err(|_| IdentityFactFailure::Malformed)?;
        let security_patch =
            SecurityPatchLevel::new(&required_property_text(snapshot, SECURITY_PATCH_PROPERTY)?)
                .map_err(|_| IdentityFactFailure::Malformed)?;
        let verified_boot = parse_verified_boot(snapshot)?;

        Ok(ParsedAndroidProperties {
            android_product,
            android_build,
            vendor_build,
            security_patch,
            verified_boot,
        })
    }

    fn parse_verified_boot(
        snapshot: &AndroidPropertySnapshot,
    ) -> Result<VerifiedBootIdentity, IdentityFactFailure> {
        let state = match required_property_text(snapshot, VERIFIED_BOOT_STATE_PROPERTY)?.as_str() {
            "green" => VerifiedBootState::Green,
            "yellow" => VerifiedBootState::Yellow,
            "orange" => VerifiedBootState::Orange,
            "red" => VerifiedBootState::Red,
            _ => return Err(IdentityFactFailure::Malformed),
        };
        let device_state = optional_property_text(snapshot, VBMETA_DEVICE_STATE_PROPERTY)?
            .map(|value| match value.as_str() {
                "locked" => Ok(true),
                "unlocked" => Ok(false),
                _ => Err(IdentityFactFailure::Malformed),
            })
            .transpose()?;
        let flash_locked = optional_property_text(snapshot, FLASH_LOCKED_PROPERTY)?
            .map(|value| match value.as_str() {
                "1" => Ok(true),
                "0" => Ok(false),
                _ => Err(IdentityFactFailure::Malformed),
            })
            .transpose()?;
        let device_locked = match (device_state, flash_locked) {
            (Some(left), Some(right)) if left != right => {
                return Err(IdentityFactFailure::Malformed);
            }
            (Some(value), Some(_) | None) | (None, Some(value)) => value,
            (None, None) => return Err(IdentityFactFailure::Absent),
        };
        if required_property_text(snapshot, VBMETA_HASH_ALGORITHM_PROPERTY)? != "sha256" {
            return Err(IdentityFactFailure::Malformed);
        }
        let vbmeta_digest =
            parse_sha256(&required_property_text(snapshot, VBMETA_DIGEST_PROPERTY)?)?;
        Ok(VerifiedBootIdentity::new(
            state,
            device_locked,
            vbmeta_digest,
        ))
    }

    fn required_property_text(
        snapshot: &AndroidPropertySnapshot,
        name: &'static str,
    ) -> Result<String, IdentityFactFailure> {
        optional_property_text(snapshot, name)?.ok_or(IdentityFactFailure::Absent)
    }

    fn product_component(
        snapshot: &AndroidPropertySnapshot,
        name: &'static str,
    ) -> Result<String, IdentityFactFailure> {
        let value = required_property_text(snapshot, name)?;
        if value.trim() != value
            || !value.is_ascii()
            || value.chars().any(char::is_control)
            || value.contains('/')
        {
            return Err(IdentityFactFailure::Malformed);
        }
        Ok(value)
    }

    fn build_fingerprint(
        snapshot: &AndroidPropertySnapshot,
        name: &'static str,
    ) -> Result<String, IdentityFactFailure> {
        let value = required_property_text(snapshot, name)?;
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(IdentityFactFailure::Malformed);
        }
        Ok(value)
    }

    fn optional_property_text(
        snapshot: &AndroidPropertySnapshot,
        name: &'static str,
    ) -> Result<Option<String>, IdentityFactFailure> {
        let value = snapshot
            .values
            .get(name)
            .ok_or(IdentityFactFailure::Malformed)?;
        match value {
            None => Ok(None),
            Some(value) if value.is_empty() => Err(IdentityFactFailure::Malformed),
            Some(value) => String::from_utf8(value.clone())
                .map(Some)
                .map_err(|_| IdentityFactFailure::Malformed),
        }
    }

    fn parse_sha256(value: &str) -> Result<Sha256Digest, IdentityFactFailure> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdentityFactFailure::Malformed);
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| IdentityFactFailure::Malformed)?;
        }
        Sha256Digest::new(bytes).map_err(|_| IdentityFactFailure::Malformed)
    }

    fn observe_active_apex_path(
        paths: &AndroidDeviceIdentityPaths,
    ) -> Result<PathBuf, IdentityFactFailure> {
        let document = read_bounded_regular_file(&paths.apex_info, MAX_APEX_INFO_BYTES as u64)?;
        parse_active_apex_path(
            &document,
            CONNECTIVITY_APEX_MODULE,
            &paths.allowed_apex_roots,
        )
    }

    pub(super) fn parse_active_apex_path(
        document: &[u8],
        module: &str,
        allowed_roots: &[PathBuf],
    ) -> Result<PathBuf, IdentityFactFailure> {
        let document = std::str::from_utf8(document).map_err(|_| IdentityFactFailure::Malformed)?;
        let mut cursor = XmlCursor::new(document);
        cursor.consume_utf8_bom();
        cursor.skip_whitespace();
        if cursor.starts_with("<?xml") {
            cursor.parse_xml_declaration()?;
            cursor.skip_whitespace();
        }
        cursor.expect("<apex-info-list")?;
        cursor.skip_whitespace();
        cursor.expect(">")?;

        let mut active = None;
        loop {
            cursor.skip_whitespace();
            if cursor.consume("</apex-info-list>") {
                break;
            }
            let attributes = parse_apex_info_element(&mut cursor)?;
            let module_name = attributes
                .get("moduleName")
                .ok_or(IdentityFactFailure::Malformed)?;
            let is_active = match attributes
                .get("isActive")
                .ok_or(IdentityFactFailure::Malformed)?
                .as_str()
            {
                "true" => true,
                "false" => false,
                _ => return Err(IdentityFactFailure::Malformed),
            };
            if module_name != module || !is_active {
                continue;
            }
            let module_path = attributes
                .get("modulePath")
                .ok_or(IdentityFactFailure::Malformed)?;
            let module_path = validate_apex_module_path(module_path, allowed_roots)?;
            if active.replace(module_path).is_some() {
                return Err(IdentityFactFailure::Malformed);
            }
        }
        cursor.skip_whitespace();
        if !cursor.is_empty() {
            return Err(IdentityFactFailure::Malformed);
        }
        active.ok_or(IdentityFactFailure::Absent)
    }

    fn parse_apex_info_element(
        cursor: &mut XmlCursor<'_>,
    ) -> Result<BTreeMap<String, String>, IdentityFactFailure> {
        cursor.expect("<apex-info")?;
        if !cursor
            .peek()
            .is_some_and(|character| character.is_ascii_whitespace())
        {
            return Err(IdentityFactFailure::Malformed);
        }

        let mut attributes = BTreeMap::new();
        loop {
            cursor.skip_whitespace();
            if cursor.consume("/>") {
                return Ok(attributes);
            }
            if cursor.consume(">") {
                cursor.skip_whitespace();
                cursor.expect("</apex-info>")?;
                return Ok(attributes);
            }

            let name = cursor.parse_attribute_name()?;
            cursor.skip_whitespace();
            cursor.expect("=")?;
            cursor.skip_whitespace();
            let value = cursor.parse_quoted_attribute_value()?;
            if attributes
                .insert(name.to_owned(), value.to_owned())
                .is_some()
            {
                return Err(IdentityFactFailure::Malformed);
            }
        }
    }

    struct XmlCursor<'a> {
        document: &'a str,
        offset: usize,
    }

    impl<'a> XmlCursor<'a> {
        const fn new(document: &'a str) -> Self {
            Self {
                document,
                offset: 0,
            }
        }

        fn remaining(&self) -> &'a str {
            &self.document[self.offset..]
        }

        fn is_empty(&self) -> bool {
            self.offset == self.document.len()
        }

        fn starts_with(&self, expected: &str) -> bool {
            self.remaining().starts_with(expected)
        }

        fn consume(&mut self, expected: &str) -> bool {
            if self.starts_with(expected) {
                self.offset += expected.len();
                true
            } else {
                false
            }
        }

        fn expect(&mut self, expected: &str) -> Result<(), IdentityFactFailure> {
            if self.consume(expected) {
                Ok(())
            } else {
                Err(IdentityFactFailure::Malformed)
            }
        }

        fn peek(&self) -> Option<char> {
            self.remaining().chars().next()
        }

        fn skip_whitespace(&mut self) {
            while self
                .peek()
                .is_some_and(|character| character.is_ascii_whitespace())
            {
                self.offset += 1;
            }
        }

        fn consume_utf8_bom(&mut self) {
            if self.starts_with("\u{feff}") {
                self.offset += '\u{feff}'.len_utf8();
            }
        }

        fn parse_xml_declaration(&mut self) -> Result<(), IdentityFactFailure> {
            self.expect("<?xml")?;
            if !self
                .peek()
                .is_some_and(|character| character.is_ascii_whitespace())
            {
                return Err(IdentityFactFailure::Malformed);
            }
            let end = self
                .remaining()
                .find("?>")
                .ok_or(IdentityFactFailure::Malformed)?;
            let declaration = &self.remaining()[..end];
            if declaration.contains(['<', '>'])
                || declaration.chars().any(char::is_control)
                || !declaration.contains("version=\"1.0\"")
            {
                return Err(IdentityFactFailure::Malformed);
            }
            self.offset += end + 2;
            Ok(())
        }

        fn parse_attribute_name(&mut self) -> Result<&'a str, IdentityFactFailure> {
            let start = self.offset;
            let first = self.peek().ok_or(IdentityFactFailure::Malformed)?;
            if !first.is_ascii_alphabetic() && first != '_' {
                return Err(IdentityFactFailure::Malformed);
            }
            self.offset += first.len_utf8();
            while self.peek().is_some_and(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
            }) {
                self.offset += 1;
            }
            Ok(&self.document[start..self.offset])
        }

        fn parse_quoted_attribute_value(&mut self) -> Result<&'a str, IdentityFactFailure> {
            self.expect("\"")?;
            let start = self.offset;
            let end = self
                .remaining()
                .find('"')
                .ok_or(IdentityFactFailure::Malformed)?;
            self.offset += end;
            let value = &self.document[start..self.offset];
            if !valid_xml_attribute_value(value) {
                return Err(IdentityFactFailure::Malformed);
            }
            self.expect("\"")?;
            Ok(value)
        }
    }

    fn valid_xml_attribute_value(value: &str) -> bool {
        if value
            .chars()
            .any(|character| character == '<' || character == '>' || character.is_control())
        {
            return false;
        }
        let mut remainder = value;
        while let Some(offset) = remainder.find('&') {
            remainder = &remainder[offset + 1..];
            let Some(end) = remainder.find(';') else {
                return false;
            };
            if !valid_xml_entity(&remainder[..end]) {
                return false;
            }
            remainder = &remainder[end + 1..];
        }
        true
    }

    fn valid_xml_entity(entity: &str) -> bool {
        if matches!(entity, "amp" | "apos" | "gt" | "lt" | "quot") {
            return true;
        }
        let parsed = if let Some(hexadecimal) = entity.strip_prefix("#x") {
            u32::from_str_radix(hexadecimal, 16).ok()
        } else if let Some(decimal) = entity.strip_prefix('#') {
            decimal.parse::<u32>().ok()
        } else {
            None
        };
        parsed.is_some_and(valid_xml_character)
    }

    const fn valid_xml_character(value: u32) -> bool {
        matches!(value, 0x9 | 0xa | 0xd | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff)
    }

    fn validate_apex_module_path(
        value: &str,
        allowed_roots: &[PathBuf],
    ) -> Result<PathBuf, IdentityFactFailure> {
        let path = PathBuf::from(value);
        let parent = path.parent().ok_or(IdentityFactFailure::Malformed)?;
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'@' | b'+')
        }) || !path.is_absolute()
            || path.extension().and_then(|value| value.to_str()) != Some("apex")
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            || !allowed_roots.iter().any(|root| {
                root.is_absolute()
                    && root.components().all(|component| {
                        matches!(component, Component::RootDir | Component::Normal(_))
                    })
                    && parent == root
            })
        {
            return Err(IdentityFactFailure::Malformed);
        }
        Ok(path)
    }

    fn observe_identity_artifact(
        source: &IdentityArtifactSource,
    ) -> Result<ArtifactIdentity, IdentityFactFailure> {
        match source {
            #[cfg(test)]
            IdentityArtifactSource::NoFollow(path) => observe_nofollow_artifact(path),
            IdentityArtifactSource::RunningExecutable => observe_artifact_with_hook(
                Path::new(PROC_SELF_EXE),
                IdentityPathKind::ProcSelfExe,
                || {},
            ),
        }
    }

    fn observe_nofollow_artifact(path: &Path) -> Result<ArtifactIdentity, IdentityFactFailure> {
        observe_artifact_with_hook(path, IdentityPathKind::NoFollow, || {})
    }

    fn observe_artifact_with_hook<F>(
        path: &Path,
        path_kind: IdentityPathKind,
        after_read: F,
    ) -> Result<ArtifactIdentity, IdentityFactFailure>
    where
        F: FnOnce(),
    {
        let (mut file, path_metadata, opened_metadata) =
            open_bounded_regular_file(path, MAX_IDENTITY_ARTIFACT_BYTES, path_kind)?;
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(IdentityFactFailure::from_io)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .filter(|total| *total <= MAX_IDENTITY_ARTIFACT_BYTES)
                .ok_or(IdentityFactFailure::Malformed)?;
            hasher.update(&buffer[..read]);
        }
        if total == 0 {
            return Err(IdentityFactFailure::Malformed);
        }
        after_read();
        verify_final_file_identity(
            path,
            path_kind,
            &file,
            &path_metadata,
            &opened_metadata,
            total,
        )?;
        let digest: [u8; 32] = hasher.finalize().into();
        let digest = Sha256Digest::new(digest).map_err(|_| IdentityFactFailure::Malformed)?;
        ArtifactIdentity::new(digest, total).map_err(|_| IdentityFactFailure::Malformed)
    }

    #[cfg(test)]
    pub(super) fn observe_test_artifact_after<F>(
        path: &Path,
        after_read: F,
    ) -> Result<ArtifactIdentity, IdentityFactFailure>
    where
        F: FnOnce(),
    {
        observe_artifact_with_hook(path, IdentityPathKind::NoFollow, after_read)
    }

    #[cfg(test)]
    pub(super) fn observe_test_running_executable() -> Result<ArtifactIdentity, IdentityFactFailure>
    {
        observe_identity_artifact(&IdentityArtifactSource::RunningExecutable)
    }

    fn read_bounded_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, IdentityFactFailure> {
        let (mut file, path_metadata, opened_metadata) =
            open_bounded_regular_file(path, limit, IdentityPathKind::NoFollow)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(opened_metadata.len().min(limit)).unwrap_or(MAX_APEX_INFO_BYTES),
        );
        file.by_ref()
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(IdentityFactFailure::from_io)?;
        if bytes.is_empty() || bytes.len() as u64 > limit {
            return Err(IdentityFactFailure::Malformed);
        }
        verify_final_file_identity(
            path,
            IdentityPathKind::NoFollow,
            &file,
            &path_metadata,
            &opened_metadata,
            bytes.len() as u64,
        )?;
        Ok(bytes)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum IdentityPathKind {
        NoFollow,
        ProcSelfExe,
    }

    fn open_bounded_regular_file(
        path: &Path,
        limit: u64,
        path_kind: IdentityPathKind,
    ) -> Result<(File, fs::Metadata, fs::Metadata), IdentityFactFailure> {
        let path_metadata = inspect_identity_path(path, path_kind)?;
        if !path_metadata.file_type().is_file() || path_metadata.len() > limit {
            return Err(IdentityFactFailure::Malformed);
        }
        let file =
            open_identity_path(path, path_kind).map_err(IdentityFactFailure::from_open_io)?;
        let opened_metadata = file.metadata().map_err(IdentityFactFailure::from_io)?;
        if !opened_metadata.file_type().is_file()
            || opened_metadata.len() > limit
            || !same_opened_file(&path_metadata, &opened_metadata)
            || metadata_changed(&path_metadata, &opened_metadata)
        {
            return Err(IdentityFactFailure::Malformed);
        }
        Ok((file, path_metadata, opened_metadata))
    }

    fn verify_final_file_identity(
        path: &Path,
        path_kind: IdentityPathKind,
        file: &File,
        path_metadata: &fs::Metadata,
        opened_metadata: &fs::Metadata,
        observed_bytes: u64,
    ) -> Result<(), IdentityFactFailure> {
        let final_metadata = file.metadata().map_err(IdentityFactFailure::from_io)?;
        if metadata_changed(opened_metadata, &final_metadata)
            || !observed_size_matches(opened_metadata, observed_bytes)
        {
            return Err(IdentityFactFailure::Malformed);
        }
        let current_path = inspect_identity_path(path, path_kind)?;
        if !current_path.file_type().is_file()
            || !same_opened_file(&current_path, &final_metadata)
            || metadata_changed(path_metadata, &current_path)
        {
            return Err(IdentityFactFailure::Malformed);
        }
        Ok(())
    }

    fn observed_size_matches(metadata: &fs::Metadata, observed_bytes: u64) -> bool {
        observed_bytes != 0 && (metadata.len() == 0 || metadata.len() == observed_bytes)
    }

    fn inspect_identity_path(
        path: &Path,
        path_kind: IdentityPathKind,
    ) -> Result<fs::Metadata, IdentityFactFailure> {
        match path_kind {
            IdentityPathKind::NoFollow => {
                let metadata = fs::symlink_metadata(path).map_err(IdentityFactFailure::from_io)?;
                if metadata.file_type().is_symlink() {
                    Err(IdentityFactFailure::Malformed)
                } else {
                    Ok(metadata)
                }
            }
            IdentityPathKind::ProcSelfExe => {
                fs::metadata(path).map_err(IdentityFactFailure::from_io)
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn open_identity_path(path: &Path, path_kind: IdentityPathKind) -> std::io::Result<File> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        let mut flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
        if path_kind == IdentityPathKind::NoFollow {
            flags |= libc::O_NOFOLLOW;
        }
        options.custom_flags(flags).open(path)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn open_identity_path(path: &Path, _path_kind: IdentityPathKind) -> std::io::Result<File> {
        fs::OpenOptions::new().read(true).open(path)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn same_opened_file(path: &fs::Metadata, descriptor: &fs::Metadata) -> bool {
        path.dev() == descriptor.dev() && path.ino() == descriptor.ino()
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn same_opened_file(_path: &fs::Metadata, _descriptor: &fs::Metadata) -> bool {
        true
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn metadata_changed(before: &fs::Metadata, after: &fs::Metadata) -> bool {
        before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.size() != after.size()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn metadata_changed(before: &fs::Metadata, after: &fs::Metadata) -> bool {
        before.len() != after.len() || before.modified().ok() != after.modified().ok()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn observe_network_namespace(
        path: &Path,
    ) -> Result<NetworkNamespaceIdentity, IdentityFactFailure> {
        let metadata = fs::metadata(path).map_err(IdentityFactFailure::from_io)?;
        NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino())
            .ok_or(IdentityFactFailure::Malformed)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn observe_network_namespace(
        _path: &Path,
    ) -> Result<NetworkNamespaceIdentity, IdentityFactFailure> {
        Err(IdentityFactFailure::Unavailable)
    }

    #[cfg(target_os = "android")]
    fn observe_system_kernel_build() -> Result<KernelBuildIdentity, IdentityFactFailure> {
        use std::ffi::CStr;
        use std::mem::MaybeUninit;

        let mut name = MaybeUninit::<libc::utsname>::zeroed();
        // SAFETY: `name` is writable storage for one `utsname`; successful `uname` initializes it.
        if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
            return Err(IdentityFactFailure::from_io(std::io::Error::last_os_error()));
        }
        // SAFETY: successful `uname` initialized the complete structure.
        let name = unsafe { name.assume_init() };
        // SAFETY: POSIX specifies both fields as NUL-terminated arrays in initialized `utsname`.
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) }
            .to_str()
            .map_err(|_| IdentityFactFailure::Malformed)?;
        // SAFETY: same initialized `utsname` contract as `release` above.
        let version = unsafe { CStr::from_ptr(name.version.as_ptr()) }
            .to_str()
            .map_err(|_| IdentityFactFailure::Malformed)?;
        KernelBuildIdentity::new(&format!("{release} {version}"))
            .map_err(|_| IdentityFactFailure::Malformed)
    }

    #[cfg(target_os = "android")]
    struct SystemAndroidPropertySource;

    #[cfg(target_os = "android")]
    impl AndroidPropertySource for SystemAndroidPropertySource {
        fn read_property(&self, name: &str) -> Result<Option<Vec<u8>>, IdentityFactFailure> {
            use std::ffi::{CStr, CString, c_char, c_void};

            #[repr(C)]
            struct PropInfo {
                _private: [u8; 0],
            }

            unsafe extern "C" {
                fn __system_property_find(name: *const c_char) -> *const PropInfo;
                fn __system_property_read_callback(
                    property: *const PropInfo,
                    callback: unsafe extern "C" fn(
                        cookie: *mut c_void,
                        name: *const c_char,
                        value: *const c_char,
                        serial: u32,
                    ),
                    cookie: *mut c_void,
                );
            }

            #[derive(Default)]
            struct CallbackResult {
                value: Option<Vec<u8>>,
                duplicate: bool,
                invalid_pointer: bool,
            }

            unsafe extern "C" fn capture_property(
                cookie: *mut c_void,
                _name: *const c_char,
                value: *const c_char,
                _serial: u32,
            ) {
                if cookie.is_null() || value.is_null() {
                    if !cookie.is_null() {
                        // SAFETY: Android invokes the callback synchronously with the exact cookie
                        // pointer supplied below, which points to a live `CallbackResult`.
                        unsafe { &mut *cookie.cast::<CallbackResult>() }.invalid_pointer = true;
                    }
                    return;
                }
                // SAFETY: `cookie` is the live callback result supplied below and Android guarantees
                // `value` is NUL-terminated for the duration of this synchronous callback.
                let result = unsafe { &mut *cookie.cast::<CallbackResult>() };
                // SAFETY: the Android property callback contract supplies a valid NUL-terminated value.
                let value = unsafe { CStr::from_ptr(value) }.to_bytes();
                if result.value.replace(value.to_vec()).is_some() {
                    result.duplicate = true;
                }
            }

            let name = CString::new(name).map_err(|_| IdentityFactFailure::Malformed)?;
            // SAFETY: `name` is a valid NUL-terminated property name for the duration of the call.
            let property = unsafe { __system_property_find(name.as_ptr()) };
            if property.is_null() {
                return Ok(None);
            }
            let mut result = CallbackResult::default();
            // SAFETY: `property` was returned by bionic and remains stable; the callback and cookie are
            // valid for this synchronous read and do not escape the call.
            unsafe {
                __system_property_read_callback(
                    property,
                    capture_property,
                    (&raw mut result).cast::<c_void>(),
                );
            }
            if result.duplicate || result.invalid_pointer {
                return Err(IdentityFactFailure::Malformed);
            }
            result
                .value
                .ok_or(IdentityFactFailure::Unavailable)
                .map(Some)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum IdentityFactFailure {
        Absent,
        Denied,
        Malformed,
        Unavailable,
    }

    impl IdentityFactFailure {
        fn from_io(error: std::io::Error) -> Self {
            match error.kind() {
                std::io::ErrorKind::NotFound => Self::Absent,
                std::io::ErrorKind::PermissionDenied => Self::Denied,
                _ => Self::Unavailable,
            }
        }

        fn from_open_io(error: std::io::Error) -> Self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Self::Malformed;
            }
            Self::from_io(error)
        }

        const fn into_observation<T>(self) -> Observation<T> {
            match self {
                Self::Absent => Observation::Absent,
                Self::Denied => Observation::Denied,
                Self::Malformed => Observation::Malformed,
                Self::Unavailable => Observation::Unavailable,
            }
        }
    }
}

#[cfg(test)]
#[path = "android_identity/tests.rs"]
mod tests;
