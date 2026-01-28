#!/system/bin/sh

# ==============================================================================
# [ Flux Boot Service ]
# Description: Android boot initialization, state detection, and dispatcher launcher.
# ==============================================================================

# Strict error handling
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

. "/data/adb/flux/scripts/const"
. "/data/adb/flux/scripts/log"

export LOG_COMPONENT="Flux"

# Load configurations (first valid)
# CACHE_CONFIG_FILE and SETTINGS_FILE are defined in const (which is sourced above), so strict mode is safe.
for file in "${CACHE_CONFIG_FILE}" "${SETTINGS_FILE}"; do
    if [ -f "${file}" ]; then
        set -a; . "${file}"; set +a
        break
    fi
done

# ==============================================================================
# [ Boot Detection ]
# ==============================================================================

_wait_for_boot() {
    local count=0
    local max=60

    while [ "${count}" -lt "${max}" ]; do
        [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && return 0
        sleep 1
        count=$((count + 1))
    done

    return 1
}

# ==============================================================================
# [ Inotify Event Watcher ]
# ==============================================================================

# Background event listener powered by inotifyd.
# Responsibilities:
# 1. Monitors the Magisk 'disable' toggle for real-time service start/stop.
# 2. Listens for internal project events (e.g., readiness flags) in the RUN_DIR.

_start_inotify_module() {
    # DISPATCHER_SCRIPT is defined in const.
    [ -f "${DISPATCHER_SCRIPT}" ] && [ ! -x "${DISPATCHER_SCRIPT}" ] && chmod +x "${DISPATCHER_SCRIPT}" 2>/dev/null
    pkill -f "inotifyd.*dispatcher" 2>/dev/null || true
    mkdir -p "${EVENTS_DIR}"
    # Monitor MAGISK_MOD_DIR (disable toggle) ::nd (New, Delete)
    # Monitor EVENTS_DIR (internal events) ::n (New only)
    nohup inotifyd "${DISPATCHER_SCRIPT}" "${MAGISK_MOD_DIR}:nd" "${EVENTS_DIR}:n" >/dev/null 2>&1 &
    return 0
}

# ==============================================================================
# [ Execution Entry Point ]
# ==============================================================================

main() {
    # FLUX_LOG is defined in const.
    [ -n "${FLUX_LOG}" ] && [ ! -t 2 ] && exec 2>>"${FLUX_LOG}"

    run "Wait for boot" _wait_for_boot || exit 1
    sleep 3

    run "Start watcher" _start_inotify_module
    sleep 1

    rm -f "${EVENT_CORE_OK}" "${EVENT_TPROXY_OK}" "${EVENT_INIT_OK}" 2>/dev/null

    [ -f "${MAGISK_MOD_DIR}/disable" ] && exit 0
    /system/bin/sh "${INIT_SCRIPT}" init
}

main
