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
. "/data/adb/flux/scripts/state"
. "/data/adb/flux/scripts/log"

# ==============================================================================
# [ Boot Detection ]
# ==============================================================================

wait_for_boot() {
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

start_inotify_module() {
    [ -f "$DISPATCHER_SCRIPT" ] && [ ! -x "$DISPATCHER_SCRIPT" ] && chmod +x "$DISPATCHER_SCRIPT" 2>/dev/null
    pkill -f "inotifyd.*dispatcher" 2>/dev/null || true
    
    # Single inotifyd monitors MAGISK_MOD_DIR for all events:
    # n=new(create), d=delete, c=create, w=close_write
    # Use 'dw' to avoid duplicate events on creation (n + w)
    nohup inotifyd "$DISPATCHER_SCRIPT" "$MAGISK_MOD_DIR:dw" >/dev/null 2>&1 &
    
    # Wait for inotifyd to be ready
    sleep 1
}

# Ensure scripts are executable
_ensure_permissions() {
    [ -f "$START_SCRIPT" ] && [ ! -x "$START_SCRIPT" ] && chmod +x "$START_SCRIPT" 2>/dev/null
    return 0
}

# ==============================================================================
# [ Main Execution ]
# ==============================================================================

main() {
    run "Wait for boot" wait_for_boot || exit 1

    sleep 3

    run "Set permissions" _ensure_permissions
    run "Start watcher" start_inotify_module
    run "Init state" state_init

    [ -f "$MAGISK_MOD_DIR/disable" ] && exit 0

    # Trigger init directly (instead of through inotify)
    run "Start service" /system/bin/sh "$INIT_SCRIPT"
}

main
