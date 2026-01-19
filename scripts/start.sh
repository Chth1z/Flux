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
# flux.rules is sourced on-demand (cold boot only)

export LOG_COMPONENT="Service"

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
# [ Service Start ]
# ==============================================================================

do_start() {
    # Pure State Machine Logic:
    # 1. RUNNING -> Return success (Assume healthy, external monitor handles crashes)
    # 2. STOPPED/FAILED/UNKNOWN -> Reset & Start
    
    if [ "$(get_service_state)" = "$STATE_RUNNING" ]; then
        log_info "Already running"
        return 0
    fi
    
    # If FAILED, force cleanup first (stop + start)
    if [ "$(get_service_state)" = "$STATE_FAILED" ]; then
        log_warn "State is FAILED, cleaning up before start..."
        sh "$CORE_SCRIPT" stop >/dev/null 2>&1 || true
        sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
    fi
    
    # State reset (covers STOPPED, FAILED, and cleanup)
    state_init
    set_service_state "$STATE_STARTING"
    
    # Check for subscription updates
    [ -f "$UPDATE_SCRIPT" ] && {
        log_debug "Checking for subscription updates..."
        sh "$UPDATE_SCRIPT" check || log_debug "Update check completed"
    }
    
    log_info "Starting services..."
    
    # Start Core and TProxy in parallel
    ( sh "$CORE_SCRIPT" start; exit $? ) &
    local core_pid=$!
    
    ( sh "$TPROXY_SCRIPT" start; exit $? ) &
    local tproxy_pid=$!
    
    log_debug "Parallel start: core=$core_pid, tproxy=$tproxy_pid"
    
    # Wait for processes to complete
    wait $core_pid 2>/dev/null; local core_exit=$?
    wait $tproxy_pid 2>/dev/null; local tproxy_exit=$?
    
    log_debug "Exit codes: core=$core_exit, tproxy=$tproxy_exit"
    
    # Barrier: wait for terminal states
    barrier_wait "${CORE_TIMEOUT:-5}"
    
    # Analyze final states
    local core_state tproxy_state
    core_state=$(get_component_state "$COMP_CORE")
    tproxy_state=$(get_component_state "$COMP_TPROXY")
    
    log_debug "Final states: core=$core_state, tproxy=$tproxy_state"
    
    # Handle failures with rollback
    if [ "$core_state" = "$STATE_FAILED" ] && [ "$tproxy_state" = "$STATE_FAILED" ]; then
        log_error "All services failed"
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
    
    # Success
    if all_components_running; then
        set_service_state "$STATE_RUNNING"
        log_info "Startup complete"
        log_info "Ready"
        prop_run
        return 0
    fi
    
    # Unexpected state
    log_error "Unexpected states: core=$core_state, tproxy=$tproxy_state"
    rollback_running_components
    set_service_state "$STATE_FAILED"
    return 1
}


# ==============================================================================
# [ Service Stop ]
# ==============================================================================

do_stop() {
    # Quick check: already stopped?
    local current_state
    current_state=$(get_service_state)
    if [ "$current_state" = "$STATE_STOPPED" ] || [ -z "$current_state" ]; then
        log_info "Already stopped"
        return 0
    fi
    
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
    barrier_wait "${CORE_TIMEOUT:-5}"
    
    if all_components_stopped; then
        set_service_state "$STATE_STOPPED"
        log_info "All stopped"
    else
        log_warn "Barrier timeout, forcing cleanup"
        sh "$CORE_SCRIPT" stop >/dev/null 2>&1 || true
        sh "$TPROXY_SCRIPT" stop >/dev/null 2>&1 || true
        set_service_state "$STATE_STOPPED"
    fi
    
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
    
    if ! is_cache_valid; then
        log_info "Cache invalid, rebuilding..."
        if ! build_all_caches; then
            log_error "Failed to build caches"
            set_service_state "$STATE_FAILED"
            return 1
        fi
    fi

    load_config_cache
    load_kernel_cache
    
    trap 'release_lock' EXIT
    
    local exit_code=0
    
    case "$action" in
        start)
            do_start || exit_code=1
            ;;
        stop)
            do_stop || exit_code=1
            ;;
        restart)
            do_stop
            do_start || exit_code=1
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status}"
            exit 1
            ;;
    esac
    
    exit $exit_code
}

main "$@"
