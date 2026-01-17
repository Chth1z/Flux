#!/system/bin/sh

# ==============================================================================
# Flux Service Manager (start.sh)
# Description: Main service orchestrator (start/stop/restart)
# ==============================================================================

# ==============================================================================
# [ Environment Setup ]
# ==============================================================================

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Load unified modules
. "$SCRIPT_DIR/flux.utils"
. "$SCRIPT_DIR/flux.data"
. "$SCRIPT_DIR/flux.rules"

export LOG_COMPONENT="Manager"

# Flux version (read from module.prop or fallback)
FLUX_VERSION=$(grep "^version=" "$PROP_FILE" 2>/dev/null | cut -d= -f2)
FLUX_VERSION="${FLUX_VERSION:-v0.9.x}"

# Show startup banner
show_banner() {
    cat << 'BANNER'
    _____ _
   |  ___| |_   ___  __
   | |_  | | | | \ \/ /
   |  _| | | |_| |>  <
   |_|   |_|\__,_/_/\_\
    
BANNER
    log_info "Flux $FLUX_VERSION"
}


# ==============================================================================
# [ File Lock Mechanism ]
# ==============================================================================

# Acquire exclusive lock - blocks until lock is available or timeout
acquire_lock() {
    local count=0
    
    # Check if lock exists and is stale (process died)
    if [ -f "$LOCK_FILE" ]; then
        local lock_pid
        lock_pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
            rm -f "$LOCK_FILE"
        fi
    fi
    
    # Wait for lock with timeout
    while [ -f "$LOCK_FILE" ]; do
        [ $count -ge $LOCK_TIMEOUT ] && return 1
        sleep 1
        count=$((count + 1))
    done
    
    # Acquire lock
    printf '%s' $$ > "$LOCK_FILE"
    
    # Setup signal handlers for graceful shutdown
    trap '_handle_signal TERM' TERM
    trap '_handle_signal INT' INT
    trap 'release_lock' EXIT
    
    return 0
}

# Internal signal handler for graceful shutdown
_handle_signal() {
    local sig="$1"
    log_warn "Received SIG$sig, initiating graceful shutdown..."
    
    # Perform cleanup
    stop_services 2>/dev/null || true
    set_service_state "$STATE_STOPPED"
    update_prop_status
    release_lock
    
    exit 0
}

# Release lock
release_lock() {
    [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
    trap - EXIT INT TERM
}


# ==============================================================================
# [ Environment & Resource Initialization ]
# ==============================================================================

# Initialize runtime environment and rotate logs
##
# @brief Initialize runtime environment
# @description Creates run directory and rotates logs
# @return 0 on success, 1 on failure
##
init_environment() {
    if [ ! -d "$RUN_DIR" ]; then
        mkdir -p "$RUN_DIR" || {
            log_error "Init: Cannot create run directory"
            prop_error "Init: rundir failed"
            return 1
        }
        chmod 0755 "$RUN_DIR"
    fi
    
    rotate_log || log_debug "Log rotation skipped"
    
    show_banner
    
    log_info "Environment initialized"
    return 0
}


# ==============================================================================
# [ Cache-Driven Initialization ]
# ==============================================================================

# Initialize with cache-first approach
# Returns: 0 on success, 1 on failure
init_with_cache() {
    if check_meta_cache_valid; then
        # Cache valid: fast path - skip validation
        log_info "Cache valid, fast boot..."
        
        if ! load_config_cache; then
            log_warn "Config cache load failed, rebuilding..."
            return 1
        fi
        
        if ! load_kernel_cache; then
            log_warn "Kernel cache load failed, rebuilding..."
            init_kernel_cache
        fi
        
        # Generate rules cache if missing
        if ! check_rules_cache_valid; then
            log_debug "Rules cache missing, generating..."
            local mode="tproxy"
            [ "${KFEAT_TPROXY:-0}" -eq 0 ] && mode="redirect"
            generate_all_rules "$mode"
        fi
        
        export_flux_config
        return 0
    fi
    
    # Cache invalid: full initialization with validation
    log_info "Cache invalid, rebuilding..."
    
    # Load config from source
    load_flux_config
    
    # Run validation
    if ! validate_all; then
        log_error "Validation failed"
        prop_error "Validation failed"
        return 1
    fi
    
    # Save caches
    save_config_cache
    
    # Generate rules cache
    local mode="tproxy"
    [ "${KFEAT_TPROXY:-0}" -eq 0 ] && mode="redirect"
    generate_all_rules "$mode"
    
    # Update meta cache
    update_meta_cache
    
    export_flux_config
    
    log_info "Caches rebuilt"
    return 0
}


# ==============================================================================
# [ Parallel Start with Barrier Synchronization ]
# ==============================================================================

##
# @brief Start all services in parallel
# @description Starts core and tproxy subsystems with barrier synchronization
# @return 0 if both succeeded, 1 if any failed
##
start_services() {
    log_info "Starting services..."
    
    # Initialize state
    state_init
    set_service_state "$STATE_STARTING"
    
    # Force cleanup stale processes
    force_cleanup
    
    # Start Core in background
    (
        sh "$CORE_SCRIPT" start
        exit $?
    ) &
    local core_pid=$!
    
    # Start TProxy in background
    (
        sh "$TPROXY_SCRIPT" start
        exit $?
    ) &
    local tproxy_pid=$!
    
    log_debug "Parallel start: core_pid=$core_pid, tproxy_pid=$tproxy_pid"
    
    # Wait for processes to complete
    wait $core_pid 2>/dev/null
    local core_exit=$?
    
    wait $tproxy_pid 2>/dev/null
    local tproxy_exit=$?
    
    log_debug "Process exit codes: core=$core_exit, tproxy=$tproxy_exit"
    
    # Barrier: wait for all components to reach terminal state
    barrier_wait "$CORE_TIMEOUT"
    
    # Analyze results
    local core_state tproxy_state
    core_state=$(get_component_state "$COMP_CORE")
    tproxy_state=$(get_component_state "$COMP_TPROXY")
    
    log_debug "Final states: core=$core_state, tproxy=$tproxy_state"
    
    # Check for failures and perform rollback
    if [ "$core_state" = "$STATE_FAILED" ] && [ "$tproxy_state" = "$STATE_FAILED" ]; then
        log_error "All services failed to start"
        prop_error "All failed"
        set_service_state "$STATE_FAILED"
        return 1
        
    elif [ "$core_state" = "$STATE_FAILED" ]; then
        log_error "Core failed, rolling back TProxy"
        prop_error "Core failed"
        rollback_component "$COMP_TPROXY"
        set_service_state "$STATE_FAILED"
        return 1
        
    elif [ "$tproxy_state" = "$STATE_FAILED" ]; then
        log_error "TProxy failed, rolling back Core"
        prop_error "TProxy failed"
        rollback_component "$COMP_CORE"
        set_service_state "$STATE_FAILED"
        return 1
    fi
    
    # Both succeeded
    if all_components_running; then
        set_service_state "$STATE_RUNNING"
        log_info "Startup complete"
        return 0
    fi
    
    # Unexpected state
    log_error "Unexpected final states: core=$core_state, tproxy=$tproxy_state"
    rollback_running_components
    set_service_state "$STATE_FAILED"
    return 1
}


# ==============================================================================
# [ Parallel Stop with Barrier ]
# ==============================================================================

stop_services() {
    log_info "Stopping services..."
    
    set_service_state "$STATE_STOPPING"
    
    # Stop TProxy and Core in parallel
    sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 &
    local tproxy_pid=$!
    
    sh "$CORE_SCRIPT" stop >/dev/null 2>&1 &
    local core_pid=$!
    
    # Wait for both
    wait $tproxy_pid 2>/dev/null || true
    wait $core_pid 2>/dev/null || true
    
    # Barrier: wait for all STOPPED
    barrier_wait "$CORE_TIMEOUT"
    
    if all_components_stopped; then
        set_service_state "$STATE_STOPPED"
        log_info "All stopped"
        return 0
    fi
    
    # Force cleanup if barrier failed
    log_warn "Barrier timeout, forcing cleanup"
    force_cleanup
    set_service_state "$STATE_STOPPED"
    return 0
}


# ==============================================================================
# [ Force Cleanup ]
# ==============================================================================

force_cleanup() {
    log_debug "Force cleanup..."
    
    sh "$CORE_SCRIPT" stop >/dev/null 2>&1 || true
    sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
}


# ==============================================================================
# [ Main Service Operations ]
# ==============================================================================

start_service_sequence() {
    local current_state
    current_state=$(get_service_state)
    
    # Check if already running - but verify the process actually exists
    if [ "$current_state" = "$STATE_RUNNING" ]; then
        # Verify core process is actually alive
        if [ -f "$PID_FILE" ]; then
            local pid
            pid=$(cat "$PID_FILE" 2>/dev/null)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                log_info "Service already running (PID: $pid)"
                return 0
            fi
        fi
        # State says RUNNING but process is dead - reset state
        log_warn "Stale RUNNING state detected, resetting..."
        state_init
        current_state="$STATE_STOPPED"
    fi
    
    # Check if transition is allowed
    if ! can_start; then
        # State might be STARTING from a crashed startup - force reset
        log_warn "Forcing state reset from: $current_state"
        state_init
    fi
    
    # Initialize with cache-first approach
    if ! init_with_cache; then
        set_service_state "$STATE_FAILED"
        return 1
    fi
    
    # Check for subscription updates (interval-based)
    if [ -f "$UPDATE_SCRIPT" ]; then
        log_debug "Checking for subscription updates..."
        sh "$UPDATE_SCRIPT" check || log_debug "Update check completed"
    fi
    
    # Start services with barrier sync and rollback
    if ! start_services; then
        return 1
    fi
    
    log_info "Ready"
    prop_run
    return 0
}

stop_service_sequence() {
    local current_state
    current_state=$(get_service_state)
    
    # Check if already stopped
    if [ "$current_state" = "$STATE_STOPPED" ]; then
        log_info "Already stopped"
        return 0
    fi
    
    # Stop services
    stop_services
    
    log_info "Service stopped"
    prop_stop
    return 0
}

# ==============================================================================
# [ Entry Point ]
# ==============================================================================

main() {
    local action="${1:-}"
    
    # Acquire lock to prevent concurrent operations
    if ! acquire_lock; then
        log_error "Another operation is in progress, please wait"
        exit 1
    fi
    
    init_environment || exit 1
    
    trap 'release_lock' EXIT
    
    local exit_code=0
    
    case "$action" in
        start)
            start_service_sequence || exit_code=1
            ;;
        stop)
            stop_service_sequence || exit_code=1
            ;;
        restart)
            stop_service_sequence
            start_service_sequence || exit_code=1
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status}"
            exit 1
            ;;
    esac
    
    exit $exit_code
}

main "$@"
