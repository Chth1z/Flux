#!/system/bin/sh

# Rust-only package placement glue. Runtime migration and cleanup stay in Rust.
set -u

SKIPUNZIP=1

readonly FLUX_DIR="/data/adb/flux"
INSTALL_STAGE="/data/adb/flux.install.$$"

cleanup_install_stage() {
    [ -z "${INSTALL_STAGE}" ] || rm -rf "${INSTALL_STAGE}"
}

[ "${BOOTMODE:-false}" = "true" ] || abort "! Boot-mode installation is required"
[ ! -e "${FLUX_DIR}" ] || abort "! Rust-only installation requires an empty ${FLUX_DIR}"
[ ! -e "${INSTALL_STAGE}" ] || abort "! Temporary install path already exists"

trap 'cleanup_install_stage' EXIT
trap 'exit 130' INT TERM
mkdir -p "${INSTALL_STAGE}" || abort "! Cannot create the runtime staging directory"

unzip -o "${ZIPFILE}" \
    'module.prop' 'uninstall.sh' 'webroot/*' 'LICENSE' \
    -d "${MODPATH}" >&2 || abort "! Cannot extract module files"
unzip -p "${ZIPFILE}" 'flux_service.sh' \
    >"${MODPATH}/service.sh" || abort "! Cannot install flux_service.sh"
unzip -o "${ZIPFILE}" 'bin/*' 'conf/*' \
    -d "${INSTALL_STAGE}" >&2 || abort "! Cannot extract the runtime payload"

[ -f "${INSTALL_STAGE}/bin/fluxd" ] || abort "! Missing bin/fluxd"
[ -f "${INSTALL_STAGE}/bin/sing-box" ] || abort "! Missing engine binary"
[ -f "${INSTALL_STAGE}/conf/flux.toml" ] || abort "! Missing desired state"
[ -f "${INSTALL_STAGE}/conf/template.json" ] || abort "! Missing engine template"
[ -f "${INSTALL_STAGE}/conf/manifest.json" ] || abort "! Missing package manifest"

set_perm_recursive "${INSTALL_STAGE}" 0 0 0755 0644
set_perm_recursive "${INSTALL_STAGE}/bin" 0 0 0755 0700
set_perm_recursive "${MODPATH}" 0 0 0755 0644
set_perm "${MODPATH}/service.sh" 0 0 0700
set_perm "${MODPATH}/uninstall.sh" 0 0 0700

mv "${INSTALL_STAGE}" "${FLUX_DIR}" || abort "! Cannot publish the runtime payload"
INSTALL_STAGE=""
trap - EXIT INT TERM
ui_print "- Installed Rust-only Flux package skeleton"
