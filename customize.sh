#!/system/bin/sh

# Native package placement glue. Runtime migration and cleanup stay in Rust.
set -u

SKIPUNZIP=1
umask 077

readonly FLUX_DIR="/data/adb/flux"
INSTALL_STAGE="/data/adb/flux.install.$$"

cleanup_install_stage() {
    [ -z "${INSTALL_STAGE}" ] || rm -rf "${INSTALL_STAGE}"
}

interrupt_install() {
    exit 130
}

[ "${BOOTMODE:-false}" = "true" ] || abort "! Boot-mode installation is required"
[ ! -e "${FLUX_DIR}" ] || abort "! Native development installation requires an empty ${FLUX_DIR}"
[ ! -e "${INSTALL_STAGE}" ] || abort "! Temporary install path already exists"

trap cleanup_install_stage EXIT
trap interrupt_install INT TERM
mkdir "${INSTALL_STAGE}" || abort "! Cannot create the runtime staging directory"

unzip -o "${ZIPFILE}" \
    'module.prop' 'uninstall.sh' 'webroot/*' 'LICENSE' \
    -d "${MODPATH}" >&2 || abort "! Cannot extract module files"
unzip -p "${ZIPFILE}" 'flux_service.sh' \
    >"${MODPATH}/service.sh" || abort "! Cannot install flux_service.sh"
unzip -o "${ZIPFILE}" 'bin/*' 'conf/*' \
    -d "${INSTALL_STAGE}" >&2 || abort "! Cannot extract the runtime payload"

[ -f "${INSTALL_STAGE}/bin/fluxd" ] || abort "! Missing bin/fluxd"
[ -f "${INSTALL_STAGE}/bin/sing-box" ] || abort "! Missing bin/sing-box"
[ -f "${INSTALL_STAGE}/conf/flux.toml" ] || abort "! Missing conf/flux.toml"
[ -f "${INSTALL_STAGE}/conf/template.json" ] || abort "! Missing conf/template.json"
[ -f "${INSTALL_STAGE}/conf/manifest.json" ] || abort "! Missing conf/manifest.json"

set_perm_recursive "${INSTALL_STAGE}" 0 0 0755 0644
set_perm_recursive "${INSTALL_STAGE}/bin" 0 0 0755 0700
set_perm_recursive "${MODPATH}" 0 0 0755 0644
set_perm "${MODPATH}/service.sh" 0 0 0700
set_perm "${MODPATH}/uninstall.sh" 0 0 0700

# Retire exact Flux-owned global launchers from pre-module-local development builds.
rm -f \
    /data/adb/service.d/flux_service.sh \
    /data/adb/ksu/service.d/flux_service.sh \
    2>/dev/null || true

[ ! -e "${FLUX_DIR}" ] || abort "! Runtime root appeared during installation"
mv "${INSTALL_STAGE}" "${FLUX_DIR}" || abort "! Cannot publish the runtime payload"
INSTALL_STAGE=""
trap - EXIT INT TERM
ui_print "- Installed native Flux development package"
