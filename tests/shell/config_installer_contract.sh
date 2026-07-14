#!/usr/bin/sh

set -eu

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
readonly TEST_DIR
REPO_ROOT=$(CDPATH='' cd -- "${TEST_DIR}/../.." && pwd)
readonly REPO_ROOT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_line() {
    local expected="${1}"
    local file="${2}"

    grep -Fqx -- "${expected}" "${file}" ||
        fail "${file} omitted expected line: ${expected}"
}

assert_multiline_value() {
    local key="${1}"
    local expected="${2}"
    local file="${3}"
    local actual

    actual=$(awk -v key="${key}" '
        $0 ~ "^" key "=" { capture = 1 }
        capture { print }
        capture && /"$/ { exit }
    ' "${file}")

    [ "${actual}" = "${expected}" ] || {
        printf '%s\n' '--- expected ---' >&2
        printf '%s\n' "${expected}" >&2
        printf '%s\n' '--- actual ---' >&2
        printf '%s\n' "${actual}" >&2
        fail "${key} migration changed its quoted multiline value"
    }
}

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM

# Load the real migration key list and helper without executing the installer.
sed -n '/^readonly MIGRATE_KEYS="/,/^}$/p' "${REPO_ROOT}/customize.sh" \
    >"${tmp_dir}/migration.sh"
sed -n '/^_restore_install_backup()/,/^}/p' "${REPO_ROOT}/customize.sh" \
    >"${tmp_dir}/installer-recovery.sh"
sed -n '/^_installer_cleanup()/,/^}/p' "${REPO_ROOT}/customize.sh" \
    >>"${tmp_dir}/installer-recovery.sh"
ui_print() { :; }
# shellcheck source=/dev/null
. "${tmp_dir}/migration.sh"
# shellcheck source=/dev/null
. "${tmp_dir}/installer-recovery.sh"

recovery_backup="${tmp_dir}/recovery-backup"
recovery_conf="${tmp_dir}/recovery-conf"
recovery_flux="${tmp_dir}/recovery-flux"
mkdir -p "${recovery_backup}" "${recovery_conf}" "${recovery_flux}/tmp"
for file in flux.toml settings.ini template.json addrsyncd.toml; do
    printf 'old-%s\n' "${file}" >"${recovery_backup}/${file}"
    printf 'new-%s\n' "${file}" >"${recovery_conf}/${file}"
done
INSTALL_BACKUP_DIR="${recovery_backup}"
INSTALL_RESTORE_CONFIG_ON_EXIT=1
CONF_DIR="${recovery_conf}"
FLUX_DIR="${recovery_flux}"
_installer_cleanup
for file in flux.toml settings.ini template.json addrsyncd.toml; do
    assert_line "old-${file}" "${recovery_conf}/${file}"
done
[ ! -e "${recovery_backup}" ] || fail "successful recovery retained its temporary backup"

failure_backup="${tmp_dir}/failed-recovery-backup"
failure_conf="${tmp_dir}/failed-recovery-conf"
mkdir -p "${failure_backup}" "${failure_conf}"
printf 'old-settings\n' >"${failure_backup}/settings.ini"
(
    cp() { return 1; }
    INSTALL_BACKUP_DIR="${failure_backup}"
    INSTALL_RESTORE_CONFIG_ON_EXIT=1
    CONF_DIR="${failure_conf}"
    FLUX_DIR="${tmp_dir}/failed-recovery-flux"
    _installer_cleanup
)
[ -f "${failure_backup}/settings.ini" ] ||
    fail "failed recovery deleted the only remaining user backup"

grep -Fq 'INSTALL_RESTORE_CONFIG_ON_EXIT=1' "${REPO_ROOT}/customize.sh" ||
    fail "installer does not arm configuration rollback before extraction"
grep -Fq 'abort "! Failed to back up settings.ini"' "${REPO_ROOT}/customize.sh" ||
    fail "settings backup failure is not fatal"
grep -Fq 'abort "! Failed to restore template.json"' "${REPO_ROOT}/customize.sh" ||
    fail "template restore failure is not fatal"
grep -Fq 'abort "! Failed to restore addrsyncd.toml"' "${REPO_ROOT}/customize.sh" ||
    fail "addrsyncd restore failure is not fatal"

legacy_settings="${TEST_DIR}/fixtures/installer-settings-legacy.ini"
migrated_settings="${tmp_dir}/settings.ini"
cp "${REPO_ROOT}/conf/settings.ini" "${migrated_settings}"

_migrate_settings "${legacy_settings}" "${migrated_settings}" ||
    fail "valid legacy settings did not migrate"

assert_line 'PROXY_MODE="tun"' "${migrated_settings}"
assert_line 'TUN_INTERFACE="legacy-tun9"' "${migrated_settings}"
assert_line 'TUN_INET4_ADDRESS="10.222.0.1/30"' "${migrated_settings}"
assert_line 'TUN_INET6_ADDRESS="fd12:3456::1/126"' "${migrated_settings}"
assert_line 'TUN_MTU=8123' "${migrated_settings}"
assert_line 'APP_USER_SCOPE="list"' "${migrated_settings}"
assert_multiline_value \
    APP_LIST \
    'APP_LIST="com.example.one
com.example.two"' \
    "${migrated_settings}"
assert_multiline_value \
    APP_USER_LIST \
    'APP_USER_LIST="0
10
999"' \
    "${migrated_settings}"

# Runtime-derived and unknown legacy fields must not leak into the new template.
if grep -Eq '^(PROXY_PORT|FAKEIP_V4_RANGE|FAKEIP_V6_RANGE|UNSUPPORTED_LEGACY_KEY)=' \
    "${migrated_settings}"; then
    fail "migration appended a runtime-derived or unknown legacy setting"
fi

empty_legacy_settings="${tmp_dir}/empty-legacy-settings.ini"
empty_migrated_settings="${tmp_dir}/empty-migrated-settings.ini"
: >"${empty_legacy_settings}"
cp "${REPO_ROOT}/conf/settings.ini" "${empty_migrated_settings}"
_migrate_settings "${empty_legacy_settings}" "${empty_migrated_settings}" ||
    fail "empty legacy settings did not preserve the packaged schema"
cmp -s "${REPO_ROOT}/conf/settings.ini" "${empty_migrated_settings}" ||
    fail "empty legacy settings replaced the packaged schema with an empty file"

if _migrate_settings "${legacy_settings}" "${tmp_dir}/missing/settings.ini" \
    2>"${tmp_dir}/migration-failure.err"; then
    fail "migration unexpectedly accepted an unreadable target"
fi
grep -Fq 'abort "! Failed to migrate settings.ini"' "${REPO_ROOT}/customize.sh" ||
    fail "installer does not make settings migration failure fatal"

log_error() { printf '%s\n' "$*" >&2; }
log_warn() { printf '%s\n' "$*" >&2; }
# shellcheck source=../../scripts/config
. "${REPO_ROOT}/scripts/config"

supported="${tmp_dir}/supported.ini"
cat >"${supported}" <<'EOF'
PROXY_MODE="tproxy"
BYPASS_SET_BACKEND="zone"
TUN_INTERFACE="reserved_tun0"
EXCLUDE_INTERFACES="wlan+
rmnet+"
EOF
SETTINGS_FILE="${supported}"
_process_settings >"${tmp_dir}/supported.out" 2>"${tmp_dir}/supported.err" ||
    fail "supported Phase 1 settings were rejected"
assert_line "PROXY_MODE='tproxy'" "${tmp_dir}/supported.out"
assert_line "BYPASS_SET_BACKEND='zone'" "${tmp_dir}/supported.out"
assert_line "TUN_INTERFACE='reserved_tun0'" "${tmp_dir}/supported.out"
assert_line "EXCLUDE_INTERFACES='wlan+ rmnet+'" "${tmp_dir}/supported.out"

rejected_tun="${tmp_dir}/rejected-tun.ini"
printf '%s\n' 'PROXY_MODE="tun"' >"${rejected_tun}"
SETTINGS_FILE="${rejected_tun}"
if _process_settings >"${tmp_dir}/tun.out" 2>"${tmp_dir}/tun.err"; then
    fail "normal configuration admitted reserved TUN mode"
fi
grep -Fq "PROXY_MODE: invalid value 'tun' (allowed: tproxy)" "${tmp_dir}/tun.err" ||
    fail "TUN rejection did not identify the admitted mode"

for backend in ipset auto; do
    rejected_backend="${tmp_dir}/rejected-${backend}.ini"
    printf 'BYPASS_SET_BACKEND="%s"\n' "${backend}" >"${rejected_backend}"
    SETTINGS_FILE="${rejected_backend}"
    if _process_settings \
        >"${tmp_dir}/${backend}.out" 2>"${tmp_dir}/${backend}.err"; then
        fail "normal configuration admitted reserved ${backend} backend"
    fi
    grep -Fq "BYPASS_SET_BACKEND: invalid value '${backend}' (allowed: zone)" \
        "${tmp_dir}/${backend}.err" ||
        fail "${backend} rejection did not identify the admitted backend"
done

printf 'config and installer contract shell tests: PASS\n'
