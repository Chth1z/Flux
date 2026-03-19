#!/system/bin/sh

# ==============================================================================
# [ Flux Boot Service ]
# Description: Android boot initialization, state detection, and dispatcher launcher.
# ==============================================================================
# Runtime note:
#   This script only waits boot, starts inotify watcher, and triggers init once.
#   Orchestration decisions are delegated to dispatcher via events.
# ==============================================================================

# Strict error handling
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

# ==============================================================================
# [ Environment & Logging ]
# ==============================================================================

. "/data/adb/flux/scripts/lib"
. "/data/adb/flux/scripts/log"

readonly LOG_COMPONENT="Flux"

load_config || exit 1

# ==============================================================================
# [ Boot Detection ]
# ==============================================================================

_wait_for_boot() {
    local count=0
    while [ "${count}" -lt "${BOOT_TIMEOUT}" ]; do
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
# 2. Listens for config file changes for hot-reload.

_start_inotify_module() {
    if [ -f "${DISPATCHER_SCRIPT}" ] && [ ! -x "${DISPATCHER_SCRIPT}" ]; then
        chmod +x "${DISPATCHER_SCRIPT}" || return 1
    fi
    pkill -f "inotifyd.*dispatcher" >/dev/null 2>&1 || true
    # Monitor MAGISK_MOD_DIR (disable toggle) ::nd (New, Delete)
    # Monitor CONF_DIR (config changes) ::y (Close-Write)
    nohup inotifyd "${DISPATCHER_SCRIPT}" "${MAGISK_MOD_DIR}:nd" "${CONF_DIR}:y" >/dev/null 2>&1 &
}

# ==============================================================================
# [ Execution Entry Point ]
# ==============================================================================

main() {
    [ -n "${FLUX_LOG}" ] && [ ! -t 2 ] && exec 2>>"${FLUX_LOG}"

    # Clear stale dispatcher locks from previous dirty shutdown
    rm -rf "${DISPATCH_LOCK_DIR}" 2>/dev/null || true

    run "Wait for boot" _wait_for_boot || exit 1
    run -v "Start watcher" _start_inotify_module || exit 1

    [ -f "${MAGISK_MOD_DIR}/disable" ] && exit 0

    touch "${BOOT_TRIGGER}"
}

main "$@"
