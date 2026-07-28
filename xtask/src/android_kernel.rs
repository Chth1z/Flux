const MINIMUM_SUPPORTED_VERSION: (u32, u32) = (5, 10);

pub(super) fn validate_supported_release(release: &str) -> Result<(), String> {
    let (major, minor) = parse_release(release).ok_or_else(|| {
        format!(
            "Android kernel release {release:?} is outside the required major.minor.patch release grammar"
        )
    })?;
    if (major, minor) < MINIMUM_SUPPORTED_VERSION {
        return Err(format!(
            "Android kernel release {release:?} is below the supported 5.10 floor"
        ));
    }
    Ok(())
}

pub(super) fn meets_supported_floor(release: &str) -> bool {
    validate_supported_release(release).is_ok()
}

fn parse_release(release: &str) -> Option<(u32, u32)> {
    if release.is_empty() || !release.is_ascii() {
        return None;
    }
    let (major, remainder) = release.split_once('.')?;
    let (minor, patch_and_suffix) = remainder.split_once('.')?;
    let major = decimal_component(major)?;
    let minor = decimal_component(minor)?;
    let patch_digits = patch_and_suffix
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if patch_digits == 0 {
        return None;
    }
    decimal_component(&patch_and_suffix[..patch_digits])?;
    let suffix = &patch_and_suffix[patch_digits..];
    if !valid_vendor_suffix(suffix) {
        return None;
    }
    Some((major, minor))
}

fn decimal_component(component: &str) -> Option<u32> {
    (!component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| component.parse::<u32>().ok())
        .flatten()
}

fn valid_vendor_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    if suffix == "+" {
        return true;
    }
    let suffix = suffix.strip_suffix('+').unwrap_or(suffix);
    let bytes = suffix.as_bytes();
    matches!(bytes.first(), Some(b'-' | b'+'))
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_floor_requires_numeric_major_minor_and_patch_prefix() {
        assert!(meets_supported_floor("5.10.0"));
        assert!(meets_supported_floor("5.10.198-android13-9-gki"));
        assert!(meets_supported_floor("6.1.0-gki"));
        assert!(meets_supported_floor(
            "5.15.104-windows-subsystem-for-android-20230927+"
        ));
        assert!(meets_supported_floor("5.10.1+"));
        assert!(!meets_supported_floor("5.9.999"));
        assert!(!meets_supported_floor("5x.10.1"));
        assert!(!meets_supported_floor("5.10x.1"));
        assert!(!meets_supported_floor("5.10"));
        assert!(!meets_supported_floor("unknown"));
        assert!(!meets_supported_floor("5.10.1."));
        assert!(!meets_supported_floor("5.10.1/garbage"));
        assert!(!meets_supported_floor("5.10.1 trailing"));
        assert!(!meets_supported_floor("5.10.1\tandroid"));
        assert!(!meets_supported_floor("5.10.1-"));
        assert!(!meets_supported_floor("5.10.1++"));
        assert!(!meets_supported_floor("5.10.4294967296-android"));
        assert!(!meets_supported_floor("4294967296.10.1-android"));
        assert!(!meets_supported_floor("5.4294967296.1-android"));
    }

    #[test]
    fn rejection_distinguishes_invalid_grammar_from_an_unsupported_version() {
        assert!(
            validate_supported_release("5.10")
                .expect_err("missing patch must fail")
                .contains("release grammar")
        );
        assert!(
            validate_supported_release("5.4.280-android")
                .expect_err("old kernel must fail")
                .contains("below the supported 5.10 floor")
        );
    }
}
