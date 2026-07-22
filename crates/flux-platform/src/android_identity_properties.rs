use flux_core::{
    AndroidBuildIdentity, AndroidProductIdentity, SecurityPatchLevel, Sha256Digest,
    VendorBuildIdentity, VerifiedBootIdentity, VerifiedBootState,
};

pub const MAX_ANDROID_IDENTITY_PROPERTY_BYTES: usize = 1_024;

pub const ANDROID_IDENTITY_PROPERTY_NAMES: [&str; 11] = [
    "ro.product.brand",
    "ro.product.name",
    "ro.product.device",
    "ro.build.fingerprint",
    "ro.vendor.build.fingerprint",
    "ro.build.version.security_patch",
    "ro.boot.verifiedbootstate",
    "ro.boot.vbmeta.device_state",
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.hash_alg",
    "ro.boot.vbmeta.digest",
];

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidIdentityPropertyError {
    Absent,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AndroidIdentityProperties {
    pub(super) android_product: AndroidProductIdentity,
    pub(super) android_build: AndroidBuildIdentity,
    pub(super) vendor_build: VendorBuildIdentity,
    pub(super) security_patch: SecurityPatchLevel,
    pub(super) verified_boot: VerifiedBootIdentity,
}

pub(crate) fn parse_android_identity_properties<'a, F>(
    property: F,
) -> Result<AndroidIdentityProperties, AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    let product_brand = product_component(&property, PRODUCT_BRAND_PROPERTY)?;
    let product_name = product_component(&property, PRODUCT_NAME_PROPERTY)?;
    let product_device = product_component(&property, PRODUCT_DEVICE_PROPERTY)?;
    let android_product =
        AndroidProductIdentity::new(&format!("{product_brand}/{product_name}/{product_device}"))
            .map_err(|_| AndroidIdentityPropertyError::Malformed)?;
    let android_build =
        AndroidBuildIdentity::new(build_fingerprint(&property, BUILD_FINGERPRINT_PROPERTY)?)
            .map_err(|_| AndroidIdentityPropertyError::Malformed)?;
    let vendor_build = VendorBuildIdentity::new(build_fingerprint(
        &property,
        VENDOR_BUILD_FINGERPRINT_PROPERTY,
    )?)
    .map_err(|_| AndroidIdentityPropertyError::Malformed)?;
    let security_patch =
        SecurityPatchLevel::new(required_property_text(&property, SECURITY_PATCH_PROPERTY)?)
            .map_err(|_| AndroidIdentityPropertyError::Malformed)?;
    let verified_boot = parse_android_verified_boot_properties(&property)?;

    Ok(AndroidIdentityProperties {
        android_product,
        android_build,
        vendor_build,
        security_patch,
        verified_boot,
    })
}

fn parse_android_verified_boot_properties<'a, F>(
    property: F,
) -> Result<VerifiedBootIdentity, AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    let state = match required_property_text(&property, VERIFIED_BOOT_STATE_PROPERTY)? {
        "green" => VerifiedBootState::Green,
        "yellow" => VerifiedBootState::Yellow,
        "orange" => VerifiedBootState::Orange,
        "red" => VerifiedBootState::Red,
        _ => return Err(AndroidIdentityPropertyError::Malformed),
    };
    let device_state = optional_property_text(&property, VBMETA_DEVICE_STATE_PROPERTY)?
        .map(|value| match value {
            "locked" => Ok(true),
            "unlocked" => Ok(false),
            _ => Err(AndroidIdentityPropertyError::Malformed),
        })
        .transpose()?;
    let flash_locked = optional_property_text(&property, FLASH_LOCKED_PROPERTY)?
        .map(|value| match value {
            "1" => Ok(true),
            "0" => Ok(false),
            _ => Err(AndroidIdentityPropertyError::Malformed),
        })
        .transpose()?;
    let device_locked = match (device_state, flash_locked) {
        (Some(left), Some(right)) if left != right => {
            return Err(AndroidIdentityPropertyError::Malformed);
        }
        (Some(value), Some(_) | None) | (None, Some(value)) => value,
        (None, None) => return Err(AndroidIdentityPropertyError::Absent),
    };
    if required_property_text(&property, VBMETA_HASH_ALGORITHM_PROPERTY)? != "sha256" {
        return Err(AndroidIdentityPropertyError::Malformed);
    }
    let vbmeta_digest = parse_sha256(required_property_text(&property, VBMETA_DIGEST_PROPERTY)?)?;
    Ok(VerifiedBootIdentity::new(
        state,
        device_locked,
        vbmeta_digest,
    ))
}

pub fn validate_android_identity_properties<'a, F>(
    property: F,
) -> Result<(), AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    parse_android_identity_properties(property).map(drop)
}

pub fn validate_android_verified_boot_properties<'a, F>(
    property: F,
) -> Result<(), AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    parse_android_verified_boot_properties(property).map(drop)
}

fn required_property_text<'a, F>(
    property: &F,
    name: &'static str,
) -> Result<&'a str, AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    optional_property_text(property, name)?.ok_or(AndroidIdentityPropertyError::Absent)
}

fn product_component<'a, F>(
    property: &F,
    name: &'static str,
) -> Result<&'a str, AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    let value = required_property_text(property, name)?;
    if value.trim() != value
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || value.contains('/')
    {
        return Err(AndroidIdentityPropertyError::Malformed);
    }
    Ok(value)
}

fn build_fingerprint<'a, F>(
    property: &F,
    name: &'static str,
) -> Result<&'a str, AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    let value = required_property_text(property, name)?;
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(AndroidIdentityPropertyError::Malformed);
    }
    Ok(value)
}

fn optional_property_text<'a, F>(
    property: &F,
    name: &'static str,
) -> Result<Option<&'a str>, AndroidIdentityPropertyError>
where
    F: Fn(&'static str) -> Option<Option<&'a [u8]>>,
{
    match property(name).ok_or(AndroidIdentityPropertyError::Malformed)? {
        None => Ok(None),
        Some(value) if value.is_empty() || value.len() > MAX_ANDROID_IDENTITY_PROPERTY_BYTES => {
            Err(AndroidIdentityPropertyError::Malformed)
        }
        Some(value) => std::str::from_utf8(value)
            .map(Some)
            .map_err(|_| AndroidIdentityPropertyError::Malformed),
    }
}

fn parse_sha256(value: &str) -> Result<Sha256Digest, AndroidIdentityPropertyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AndroidIdentityPropertyError::Malformed);
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| AndroidIdentityPropertyError::Malformed)?;
    }
    Sha256Digest::new(bytes).map_err(|_| AndroidIdentityPropertyError::Malformed)
}
