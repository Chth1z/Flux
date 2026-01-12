#!/system/bin/sh


# ==============================================================================
# Flux Service Manager (start.sh)
# Description: Orchestrator for Core and TProxy services with state machine
#              Manages lifecycle with explicit state transitions and rollback
# ==============================================================================


# ------------------------------------------------------------------------------
# [ Load Dependencies ]
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "$SCRIPT_DIR/flux.config"
. "$SCRIPT_DIR/flux.logger"
. "$SCRIPT_DIR/flux.state"
. "$SCRIPT_DIR/flux.validator"

# Set log component name
export LOG_COMPONENT="Manager"


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
    echo $$ > "$LOCK_FILE"
    trap 'release_lock' EXIT INT TERM
    return 0
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
    
    log_debug "Environment initialized"
    return 0
}


# ==============================================================================
# [ Rollback Management ]
# ==============================================================================

# Rollback is now handled within each parallel branch


# ==============================================================================
# [ Parallel Start with Branch Rollback ]
# ==============================================================================

start_services() {
    log_info "Starting services in parallel..."
    
    # Ensure clean slate
    force_cleanup
    
    local core_result=0
    local tproxy_result=0
    local core_pid tproxy_pid
    
    # Start Core in background with self-rollback on failure
    (
        if sh "$SCRIPT_DIR/flux.core" start; then
            exit 0
        else
            log_error "Core start failed"
            # Self-rollback: clean up core on failure
            sh "$SCRIPT_DIR/flux.core" stop >/dev/null 2>&1 || true
            exit 1
        fi
    ) &
    core_pid=$!
    
    # Start TProxy in background with self-rollback on failure
    (
        if sh "$TPROXY_SCRIPT" start; then
            exit 0
        else
            log_error "TProxy start failed"
            # Self-rollback: clean up tproxy on failure
            sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
            exit 1
        fi
    ) &
    tproxy_pid=$!
    
    # Wait for both to complete
    wait $core_pid
    core_result=$?
    
    wait $tproxy_pid
    tproxy_result=$?
    
    # Evaluate results and handle cross-rollback
    if [ $core_result -ne 0 ] && [ $tproxy_result -ne 0 ]; then
        log_error "All services failed to start"
        prop_error "All failed"
        return 1
    elif [ $core_result -ne 0 ]; then
        log_error "Core failed, rolling back TProxy"
        prop_error "Core failed"
        sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
        return 1
    elif [ $tproxy_result -ne 0 ]; then
        log_error "TProxy failed, rolling back Core"
        prop_error "TProxy failed"
        sh "$SCRIPT_DIR/flux.core" stop >/dev/null 2>&1 || true
        return 1
    fi
    
    log_info "All services started"
    return 0
}


# ==============================================================================
# [ Sequential Stop ]
# ==============================================================================

stop_services() {
    log_info "Stopping services..."
    
    # Stop TProxy first (removes iptables rules)
    log_debug "Stopping TProxy..."
    sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
    
    # Stop Core
    log_debug "Stopping Core..."
    sh "$SCRIPT_DIR/flux.core" stop >/dev/null 2>&1 || true
    
    log_info "All services stopped"
    return 0
}


# ==============================================================================
# [ Force Cleanup ]
# ==============================================================================

force_cleanup() {
    log_debug "Force cleanup of stale services..."
    
    sh "$SCRIPT_DIR/flux.core" stop >/dev/null 2>&1 || true
    sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
}


# ==============================================================================
# [ Main Service Operations with State Machine ]
# ==============================================================================

start_service_sequence() {
    local current_state
    current_state=$(get_state)
    
    # Check if already running
    if [ "$current_state" = "$STATE_RUNNING" ]; then
        log_info "Service already running"
        return 0
    fi
    
    # Check if transition is allowed
    if ! can_start; then
        log_error "Cannot start from state: $current_state"
        return 1
    fi
    
    # Transition to STARTING
    transition_starting
    
    # Initialize environment
    if ! init_environment; then
        transition_failed
        return 1
    fi
    
    # Run comprehensive validation
    if ! validate_all; then
        log_error "Validation failed"
        prop_error "Validation failed"
        transition_failed
        return 1
    fi
    
    # Check for subscription updates (interval-based)
    if [ -f "$UPDATE_SCRIPT" ]; then
        log_debug "Checking for subscription updates..."
        sh "$UPDATE_SCRIPT" check || log_debug "Update check completed"
    fi
    
    # Start services with rollback support
    if ! start_services; then
        transition_failed
        return 1
    fi
    
    # Transition to RUNNING
    transition_running
    
    log_info "Service ready"
    prop_run
    return 0
}

stop_service_sequence() {
    local current_state
    current_state=$(get_state)
    
    # Check if already stopped
    if [ "$current_state" = "$STATE_STOPPED" ]; then
        log_info "Service already stopped"
        return 0
    fi
    
    # Transition to STOPPING
    transition_stopping
    
    # Stop services
    stop_services
    
    # Transition to STOPPED
    transition_stopped
    
    log_info "Service stopped"
    prop_stop
    return 0
}

# Hot reload sing-box configuration (no state change, no iptables restart)
reload_service() {
    # Check state allows reload
    if ! can_reload; then
        log_error "Cannot reload: service not running (state: $(get_state))"
        return 1
    fi
    
    log_info "Reloading core configuration..."
    
    # Validate new config before reload
    if ! validate_singbox_config; then
        log_error "New config invalid, reload aborted"
        return 1
    fi
    
    if sh "$SCRIPT_DIR/flux.core" reload; then
        log_info "Core config reloaded"
        return 0
    else
        log_error "Reload failed"
        return 1
    fi
}

# Get service status
status_service() {
    local state
    state=$(get_state)
    
    echo "State: $state"
    get_state_info
    
    # Additional info if running
    if [ "$state" = "$STATE_RUNNING" ]; then
        if [ -f "$PID_FILE" ]; then
            echo "Core PID: $(cat "$PID_FILE")"
        fi
    fi
}


# ==============================================================================
# [ Entry Point ]
# ==============================================================================

main() {
    local action="${1:-}"
    
    # Validate action first
    case "$action" in
        start|stop|reload|status|restart) ;;
        *)
            echo "Usage: $0 {start|stop|reload|restart|status}"
            exit 1
            ;;
    esac
    
    # Status doesn't need lock
    if [ "$action" = "status" ]; then
        load_flux_config
        status_service
        exit 0
    fi
    
    # Acquire lock to prevent concurrent operations
    if ! acquire_lock; then
        log_error "Another operation is in progress, please wait"
        exit 1
    fi
    
    # Load configuration
    load_flux_config
    
    trap 'update_description; release_lock' EXIT
    
    local exit_code=0
    
    case "$action" in
        start)
            start_service_sequence || exit_code=1
            ;;
        stop)
            stop_service_sequence || exit_code=1
            ;;
        reload)
            reload_service || exit_code=1
            ;;
        restart)
            stop_service_sequence
            start_service_sequence || exit_code=1
            ;;
    esac
    
    exit $exit_code
}

main "$@"
