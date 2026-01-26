#!/system/bin/sh

# Flux Boot Service
# Android boot initialization and launcher

# Constants

. "/data/adb/flux/scripts/const"
. "/data/adb/flux/scripts/log"

export LOG_COMPONENT="Flux"

for file in "$CACHE_CONFIG_FILE" "$SETTINGS_FILE"; do
    if [ -f "$file" ]; then
        set -a; . "$file"; set +a
        break
    fi
done

# Boot Detection

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

# Inotify Event Watcher

_start_inotify_module() {
    [ -f "$DISPATCHER_SCRIPT" ] && [ ! -x "$DISPATCHER_SCRIPT" ] && chmod +x "$DISPATCHER_SCRIPT" 2>/dev/null
    pkill -f "inotifyd.*dispatcher" 2>/dev/null || true
    mkdir -p "$EVENTS_DIR"
    # Monitor MAGISK_MOD_DIR (disable toggle) ::nd (New, Delete)
    # Monitor EVENTS_DIR (internal events) ::n (New only)
    nohup inotifyd "$DISPATCHER_SCRIPT" "$MAGISK_MOD_DIR:nd" "$EVENTS_DIR:n" >/dev/null 2>&1 &
    return 0
}

# Execution entry point

main() {
    [ -n "$FLUX_LOG" ] && [ ! -t 2 ] && exec 2>>"$FLUX_LOG"

    run "Wait for boot" _wait_for_boot || exit 1
    sleep 3

    run "Start watcher" _start_inotify_module
    sleep 1

    rm -f "$EVENTS_DIR/core_ok" "$EVENTS_DIR/tproxy_ok" "$EVENTS_DIR/init_ok" 2>/dev/null

    [ -f "$MAGISK_MOD_DIR/disable" ] && exit 0
    /system/bin/sh "$INIT_SCRIPT" init
}

main
