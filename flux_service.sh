#!/system/bin/sh

# ==============================================================================
# Flux Boot Service (service.sh)
# Description: Android boot initialization and service launcher
# Standalone script - no dependencies
# ==============================================================================

# ==============================================================================
# [ Constants ]
# ==============================================================================

. "/data/adb/flux/scripts/const"
. "/data/adb/flux/scripts/log"

_state_init() {
    rm -f "$EVENTS_DIR/core_ok" "$EVENTS_DIR/tproxy_ok" "$EVENTS_DIR/init_ok" 2>/dev/null
    log_debug "State initialized"
}

# ==============================================================================
# [ Boot Detection ]
# ==============================================================================

_wait_for_boot() {
    local count=0
    local max=60
    
    while [ "$count" -lt "$max" ]; do
        [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && return 0
        sleep 1
        count=$((count + 1))
    done
    
    return 1
}

# ==============================================================================
# [ Inotify Module Watcher ]
# ==============================================================================

_start_inotify_module() {
    [ -f "$DISPATCHER_SCRIPT" ] && [ ! -x "$DISPATCHER_SCRIPT" ] && chmod +x "$DISPATCHER_SCRIPT" 2>/dev/null
    pkill -f "inotifyd.*dispatcher" 2>/dev/null || true
    
    mkdir -p "$EVENTS_DIR"
    
    # Monitor MAGISK_MOD_DIR (disable toggle) ::nd (New, Delete)
    # Monitor EVENTS_DIR (internal events) ::n (New only)
    nohup inotifyd "$DISPATCHER_SCRIPT" "$MAGISK_MOD_DIR:nd" "$EVENTS_DIR:n" >/dev/null 2>&1 &
}

# ==============================================================================
# [ Main Execution ]
# ==============================================================================

main() {
    run "Wait for boot" _wait_for_boot || exit 1

    sleep 3

    run "Start watcher" _start_inotify_module

    sleep 1
    
    run "Init state" _state_init

    [ -f "$MAGISK_MOD_DIR/disable" ] && exit 0

    # Trigger init directly (instead of through inotify)
    run "Start service" /system/bin/sh "$INIT_SCRIPT"
}

main
