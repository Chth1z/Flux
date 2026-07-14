#!/usr/bin/env sh

set -eu

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

skip_or_fail() {
    message="${1}"
    if [ "${FLUX_INSTALLER_TESTS_REQUIRED}" = "1" ]; then
        fail "${message}"
    fi
    printf 'SKIP: %s\n' "${message}" >&2
    exit 0
}

[ "$#" -eq 0 ] || fail "this wrapper does not accept arguments"

FLUX_INSTALLER_TESTS_REQUIRED="${FLUX_INSTALLER_TESTS_REQUIRED:-0}"
case "${FLUX_INSTALLER_TESTS_REQUIRED}" in
0 | 1) ;;
*) fail "FLUX_INSTALLER_TESTS_REQUIRED must be 0 or 1" ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) ||
    fail "cannot resolve the test directory"
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd -P) ||
    fail "cannot resolve the repository root"
readonly SCRIPT_DIR REPO_ROOT

BWRAP_COMMAND="${BWRAP:-bwrap}"
BWRAP_BIN=$(command -v "${BWRAP_COMMAND}" 2>/dev/null || true)
[ -n "${BWRAP_BIN}" ] || skip_or_fail "bubblewrap is unavailable"
[ -x "${BWRAP_BIN}" ] || skip_or_fail "bubblewrap is not executable: ${BWRAP_BIN}"
command -v zip >/dev/null 2>&1 || skip_or_fail "zip is unavailable"

if ! "${BWRAP_BIN}" \
    --tmpfs / \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --proc /proc \
    --dev /dev \
    /usr/bin/true 2>/dev/null; then
    skip_or_fail "bubblewrap namespaces are not permitted by this host"
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM
fixture="${tmp_dir}/fixture"
data_root="${tmp_dir}/data"
mkdir -p \
    "${fixture}/bin" \
    "${fixture}/scripts" \
    "${fixture}/conf" \
    "${fixture}/webroot" \
    "${data_root}/adb/flux/conf" \
    "${data_root}/adb/modules/flux"

printf 'id=flux\nname=Flux\n' >"${fixture}/module.prop"
printf '#!/system/bin/sh\nexit 0\n' >"${fixture}/flux_service.sh"
printf '<html></html>\n' >"${fixture}/webroot/index.html"
for binary in addrsyncd jq sing-box; do
    printf '%s-new\n' "${binary}" >"${fixture}/bin/${binary}"
done
printf '#!/system/bin/sh\nexit 0\n' >"${fixture}/scripts/placeholder"
for file in flux.toml settings.ini template.json addrsyncd.toml; do
    printf 'new-%s\n' "${file}" >"${fixture}/conf/${file}"
    printf 'old-%s\n' "${file}" >"${data_root}/adb/flux/conf/${file}"
done

(
    cd "${fixture}"
    zip -qr "${tmp_dir}/module.zip" .
)

set +e
"${BWRAP_BIN}" \
    --tmpfs / \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --proc /proc \
    --dev /dev \
    --dir /tmp \
    --bind "${data_root}" /data \
    --ro-bind "${REPO_ROOT}" /src \
    --ro-bind "${tmp_dir}/module.zip" /fixture/module.zip \
    --setenv BOOTMODE true \
    --setenv MAGISK_VER test \
    --setenv MODPATH /data/adb/modules/flux \
    --setenv ZIPFILE /fixture/module.zip \
    /usr/bin/sh -c '
        ui_print() { :; }
        abort() { exit 77; }
        set_perm_recursive() { :; }
        set_perm() { :; }
        . /src/customize.sh
    ' >"${tmp_dir}/installer.out" 2>"${tmp_dir}/installer.err"
installer_exit=$?
set -e

[ "${installer_exit}" -eq 77 ] ||
    fail "installer failure exit changed: expected 77, found ${installer_exit}"
for file in flux.toml settings.ini template.json addrsyncd.toml; do
    expected="old-${file}"
    actual=$(cat "${data_root}/adb/flux/conf/${file}")
    [ "${actual}" = "${expected}" ] ||
        fail "post-extraction failure did not restore ${file}"
done

printf 'installer rollback shell tests: PASS\n'
