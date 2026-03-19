#!/system/bin/sh

# ==============================================================================
# [ Flux Module Installer ]
# Description: Magisk/KernelSU/APatch installation, migration, and env detection.
# ==============================================================================

# Strict error handling
# set -eu (Disabled for compatibility with Magisk/KSU installer environment)
# [ -n "${BASH_VERSION:-}" ] && set -o pipefail

SKIPUNZIP=1

# ==============================================================================
# [ Environment Check ]
# ==============================================================================

if [ "${BOOTMODE:-false}" != "true" ]; then
    ui_print "========================================"
    ui_print "  ! ERROR: FLUX TERMINATED"
    ui_print "  ! Please install in Magisk/KSU/APatch"
    ui_print "  ! Recovery installation is not supported"
    ui_print "========================================"
    abort
fi

# ==============================================================================
# [ Constants & Paths ]
# ==============================================================================

readonly FLUX_DIR="/data/adb/flux"
readonly CONF_DIR="${FLUX_DIR}/conf"
readonly BIN_DIR="${FLUX_DIR}/bin"
readonly SCRIPTS_DIR="${FLUX_DIR}/scripts"
readonly RUN_DIR="${FLUX_DIR}/run"
readonly MODPROP="${MODPATH}/module.prop"

# Detect service.d path (KSU <10683 uses different path)
if [ "${KSU:-false}" = "true" ] && [ "${KSU_VER_CODE:-0}" -lt 10683 ]; then
    SERVICE_DIR="/data/adb/ksu/service.d"
else
    SERVICE_DIR="/data/adb/service.d"
fi

# ==============================================================================
# [ Installer UI Helpers ]
# ==============================================================================

# Note: ui_print is provided by Magisk/KernelSU/APatch installer
ui_error() { ui_print "! $1"; }
ui_success() { ui_print "[OK] $1"; }

_detect_env() {
    ui_print "- Detecting environment..."

    if [ "${KSU:-false}" = "true" ]; then
        ui_print "  > KernelSU: ${KSU_KERNEL_VER_CODE:-} (kernel) + ${KSU_VER_CODE:-} (manager)"
        sed -i "s/^name=.*/& (KernelSU)/" "${MODPROP}" 2>/dev/null
    elif [ "${APATCH:-false}" = "true" ]; then
        ui_print "  > APatch: ${APATCH_VER_CODE:-}"
        sed -i "s/^name=.*/& (APatch)/" "${MODPROP}" 2>/dev/null
    elif [ -n "${MAGISK_VER:-}" ]; then
        ui_print "  > Magisk: ${MAGISK_VER:-} (${MAGISK_VER_CODE:-})"
    else
        ui_print "  > Unknown Environment"
    fi
}

# ==============================================================================
# [ Volume Key Selection ]
# ==============================================================================

# Simplified countdown loop with getevent timeout
_choose_action() {
    local title="${1}"
    local default_action="${2}" # true = Yes/Keep, false = No/Reset
    local timeout_sec=10
    local count=0

    ui_print " "
    ui_print "● ${title}"
    ui_print "  Vol [+] : Yes / Keep"
    ui_print "  Vol [-] : No / Reset"
    ui_print "  (Timeout: ${timeout_sec}s)"

    while [ "${count}" -lt "${timeout_sec}" ]; do
        # Capture 1 event with 1s timeout
        local ev
        ev=$(timeout 1 getevent -lc 1 2>/dev/null | grep KEY_VOLUME || true)

        case "${ev}" in
        *KEY_VOLUMEUP*)
            ui_print "  > Selected: [Yes/Keep]"
            default_action="true"
            break
            ;;
        *KEY_VOLUMEDOWN*)
            ui_print "  > Selected: [No/Reset]"
            default_action="false"
            break
            ;;
        esac
        count=$((count + 1))
    done

    # Show timeout message if loop completed without selection
    [ "${count}" -ge "${timeout_sec}" ] && {
        [ "${default_action}" = "true" ] && ui_print "  > Timeout. Default: [Yes/Keep]"
        [ "${default_action}" = "false" ] && ui_print "  > Timeout. Default: [No/Reset]"
    }

    # Clear event buffer
    timeout 1 getevent -cl >/dev/null 2>&1

    [ "${default_action}" = "true" ]
}

# ==============================================================================
# [ Settings Migration Engine ]
# ==============================================================================

# Incremental settings migration logic to preserve user configuration across updates.
# Implementation Note: Uses AWK to safely extract values from existing .ini files,
# supporting multi-line quoted values and ensuring atomic replacement in the new config.
# Note: CORE_TIMEOUT, PROXY_TCP_PORT, PROXY_UDP_PORT, DNS_PORT are now read from config.json
readonly MIGRATE_KEYS="
SUBSCRIPTION_URL
UPDATE_TIMEOUT
RETRY_COUNT
UPDATE_INTERVAL
PREF_CLEANUP_EMOJI
LOG_LEVEL
LOG_MAX_SIZE
CORE_USER
CORE_GROUP
CORE_TIMEOUT
MOBILE_INTERFACE
WIFI_INTERFACE
HOTSPOT_INTERFACE
USB_INTERFACE
PROXY_MOBILE
PROXY_WIFI
PROXY_HOTSPOT
PROXY_USB
PROXY_IPV6
ROUTING_MARK
APP_PROXY_MODE
APP_LIST
MSS_CLAMP_ENABLE
EXCLUDE_INTERFACES
UPDATER_EXCLUDE_REMARKS
UPDATER_RENAME_RULES
UPDATER_MAX_TAG_LENGTH
"

_migrate_settings() {
    local backup_file="${1}"
    local target_file="${2}"
    local tmp_file

    [ ! -f "${backup_file}" ] && return 0

    ui_print "  > Migrating settings (incremental)..."

    tmp_file=$(mktemp) || return 1
    awk -v keys="${MIGRATE_KEYS}" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        function quote_start(rhs,   t, q, rest) {
            t = trim(rhs)
            q = substr(t, 1, 1)
            if (q != "\"" && q != "'"'"'") return ""
            rest = substr(t, 2)
            return (index(rest, q) == 0) ? q : ""
        }
        BEGIN {
            n = split(keys, arr, /[[:space:]]+/)
            for (i = 1; i <= n; i++) if (arr[i] != "") keep[arr[i]] = 1

            phase = 0
            in_bq = 0
            bq_key = ""
            bq_quote = ""
            bq_val = ""

            skip_target = 0
            target_quote = ""
        }
        FNR == 1 {
            phase++
        }
        phase == 1 {
            line = $0

            if (!in_bq) {
                if (line ~ /^[A-Z0-9_]+[[:space:]]*=/) {
                    key = line
                    sub(/[[:space:]]*=.*/, "", key)

                    if (key in keep) {
                        rhs = line
                        sub(/^[^=]*=[[:space:]]*/, "", rhs)

                        q = quote_start(rhs)
                        if (q != "") {
                            in_bq = 1
                            bq_key = key
                            bq_quote = q
                            bq_val = rhs
                        } else {
                            map[key] = rhs
                        }
                    }
                }
            } else {
                bq_val = bq_val "\n" line
                if (index(line, bq_quote) > 0) {
                    map[bq_key] = bq_val
                    in_bq = 0
                    bq_key = ""
                    bq_quote = ""
                    bq_val = ""
                }
            }
            next
        }
        phase == 2 {
            line = $0

            if (skip_target) {
                if (index(line, target_quote) > 0) skip_target = 0
                next
            }

            if (line ~ /^[A-Z0-9_]+[[:space:]]*=/) {
                key = line
                sub(/[[:space:]]*=.*/, "", key)

                if (key in map) {
                    print key "=" map[key]
                    restored[key] = 1

                    rhs = line
                    sub(/^[^=]*=[[:space:]]*/, "", rhs)
                    q = quote_start(rhs)
                    if (q != "") {
                        skip_target = 1
                        target_quote = q
                    }
                    next
                }
            }

            print line
        }
        END {
            n = split(keys, arr, /[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                key = arr[i]
                if (key == "") continue
                if ((key in map) && !(key in restored)) {
                    print key "=" map[key]
                }
            }
        }
    ' "${backup_file}" "${target_file}" >"${tmp_file}"

    if [ $? -ne 0 ]; then
        rm -f "${tmp_file}"
        return 1
    fi

    mv -f "${tmp_file}" "${target_file}"
    ui_print "     ↳ settings.ini: restored"
    return 0
}

# ==============================================================================
# [ Main Installation Orchestration ]
# ==============================================================================

main() {
    _detect_env

    # 1. Backup config files before overwriting
    local tmp_backup
    tmp_backup=$(mktemp -d 2>/dev/null) || abort "! Failed to create temporary backup directory"
    mkdir -p "${tmp_backup}"

    # Ensure cleanup on exit (Use double quotes to expand tmp_backup immediately)
    trap "rm -rf \"${tmp_backup}\"; rm -rf \"${FLUX_DIR}/tmp\" 2>/dev/null" EXIT INT TERM

    local has_settings=false has_template=false has_addrsyncd=false

    if [ -d "${FLUX_DIR}" ]; then
        ui_print "- Backing up configuration files..."
        # Backup settings.ini (will auto-migrate)
        if [ -f "${CONF_DIR}/settings.ini" ]; then
            cp -f "${CONF_DIR}/settings.ini" "${tmp_backup}/settings.ini"
            has_settings=true
        fi
        # Backup template.json template (user choice)
        if [ -f "${CONF_DIR}/template.json" ]; then
            cp -f "${CONF_DIR}/template.json" "${tmp_backup}/template.json"
            has_template=true
        fi
        # Backup addrsyncd.toml (user choice)
        if [ -f "${CONF_DIR}/addrsyncd.toml" ]; then
            cp -f "${CONF_DIR}/addrsyncd.toml" "${tmp_backup}/addrsyncd.toml"
            has_addrsyncd=true
        fi
    fi

    # 2. Extract module files to MODPATH (for Magisk)
    ui_print "- Extracting module files..."
    unzip -o "${ZIPFILE}" 'module.prop' 'webroot/*' -d "${MODPATH}" >&2 || abort "! Failed to extract module.prop"

    # Deploy flux_service.sh to service.d
    mkdir -p "${SERVICE_DIR}" || abort "! Failed to create service directory"
    unzip -o "${ZIPFILE}" 'flux_service.sh' -d "${SERVICE_DIR}" >&2 || abort "! Failed to extract service script"

    # 3. Clear and recreate FLUX_DIR structure
    rm -rf "${BIN_DIR}" "${SCRIPTS_DIR}" 2>/dev/null
    # Clear cache to prevent rule inheritance issues on version mismatch
    rm -rf "${FLUX_DIR}/cache" 2>/dev/null

    unzip -o "${ZIPFILE}" 'bin/*' 'scripts/*' 'conf/*' -d "${FLUX_DIR}" >&2 || abort "! Failed to extract module files"
    # Rename default if template was extracted as singbox.json (for zip compatibility)
    [ -f "${CONF_DIR}/singbox.json" ] && mv -f "${CONF_DIR}/singbox.json" "${CONF_DIR}/template.json"

    # 4. Handle configuration restoration
    ui_print " "
    ui_print "=== Configuration ==="

    # 4.1 settings.ini - Auto migrate
    if [ "${has_settings}" = "true" ]; then
        ui_print "- Migrating settings.ini..."
        _migrate_settings "${tmp_backup}/settings.ini" "${CONF_DIR}/settings.ini"
    else
        ui_print "- Using default settings.ini"
    fi

    # 4.2 template.json - User choice
    if [ "${has_template}" = "true" ]; then
        if _choose_action "Keep [template.json]?" "true"; then
            cp -f "${tmp_backup}/template.json" "${CONF_DIR}/template.json"
            ui_print "  > template.json: restored"
        else
            ui_print "  > template.json: reset to default"
        fi
    fi

    # 4.3 addrsyncd.toml - User choice
    if [ "${has_addrsyncd}" = "true" ]; then
        if _choose_action "Keep [addrsyncd.toml]?" "true"; then
            cp -f "${tmp_backup}/addrsyncd.toml" "${CONF_DIR}/addrsyncd.toml"
            ui_print "  > addrsyncd.toml: restored"
        else
            ui_print "  > addrsyncd.toml: reset to default"
        fi
    fi

    # 5. Set Permissions
    ui_print "- Setting permissions..."
    set_perm_recursive "${MODPATH}" 0 0 0755 0644
    set_perm_recursive "${FLUX_DIR}" 0 0 0755 0644
    set_perm_recursive "${BIN_DIR}" 0 0 0755 0700
    set_perm_recursive "${SCRIPTS_DIR}" 0 0 0755 0700
    set_perm "${SERVICE_DIR}/flux_service.sh" 0 0 0700

    chmod ugo+x "${BIN_DIR}"/* 2>/dev/null || abort "! Failed to set executable bits for binaries"
    chmod ugo+x "${SCRIPTS_DIR}"/* 2>/dev/null || abort "! Failed to set executable bits for scripts"

    # 6. Cleanup
    rm -rf "${tmp_backup}"
    rm -rf "${FLUX_DIR}/tmp" 2>/dev/null || abort "! Failed to clean temporary files"

    ui_success "Installation Complete!"
}

main
