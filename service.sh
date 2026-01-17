#!/system/bin/sh

# ==============================================================================
# Flux Boot Service (service.sh)
# Description: Android boot initialization and service launcher
# ==============================================================================

# ==============================================================================
# [ Environment Setup ]
# ==============================================================================

# Load system configuration (absolute paths for boot safety)
. "/data/adb/flux/scripts/flux.utils"
. "/data/adb/flux/scripts/flux.data"

# Ensure run directory exists for logging
[ ! -d "$RUN_DIR" ] && mkdir -p "$RUN_DIR" && chmod 0755 "$RUN_DIR"

load_log_config
export LOG_COMPONENT="Service"

# ==============================================================================
# [ Boot Detection ]
# ==============================================================================

# Wait for the Android system to signal boot completion
wait_for_boot() {
    local boot_wait_count=0
    local MAX_BOOT_WAIT=60
    
    while [ "$boot_wait_count" -lt "$MAX_BOOT_WAIT" ]; do
        # Check property for finished boot
        if [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ]; then
            log_debug "System boot completed (waited ${boot_wait_count}s)"
            return 0
        fi
        
        sleep 1
        boot_wait_count=$((boot_wait_count + 1))
    done
    
    log_error "Timeout waiting for boot completion after ${MAX_BOOT_WAIT}s"
    return 1
}

# ==============================================================================
# [ Inotify Managers ]
# ==============================================================================

# Launch inotifyd watcher for module toggle (disable file)
start_inotify_module() {
    local handler="$SCRIPTS_DIR/flux.mod.inotify"
    local watch_dir="$MAGISK_MOD_DIR"
    
    # Ensure handler is executable
    [ -f "$handler" ] && chmod +x "$handler" 2>/dev/null
    
    # Kill any existing instance
    pkill -f "inotifyd.*flux.mod.inotify" 2>/dev/null || true
    
    # Start inotifyd watching for create(n) and delete(d) events
    inotifyd "$handler" "$watch_dir:nd" &
    
    log_info "Module toggle watcher started (monitoring $watch_dir)"
}

# ==============================================================================
# [ Main Execution ]
# ==============================================================================

main() {
    # Wait for Android boot completion
    wait_for_boot || exit 1
    
    # Additional delay for system stability
    sleep 5
    
    # Verify start script
    [ ! -f "$START_SCRIPT" ] && {
        log_error "Start script not found: $START_SCRIPT"
        exit 1
    }
    
    # Ensure start script is executable
    [ ! -x "$START_SCRIPT" ] && chmod +x "$START_SCRIPT" 2>/dev/null
    
    # Launch module toggle watcher (always active for reactive control)
    start_inotify_module
    
    # Check if module is disabled
    if [ -f "$MAGISK_MOD_DIR/disable" ]; then
        log_info "Module is disabled, skipping service start"
        exit 0
    fi
     
    # Start services
    log_info "Starting Flux services..."
    /system/bin/sh "$START_SCRIPT" start
}

main
