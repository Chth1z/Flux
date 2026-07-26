#!/system/bin/sh

# ==============================================================================
# [ Flux Boot Service ]
# Description: Module-local fluxd watchdog.
# ==============================================================================

set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

readonly MODDIR="${0%/*}"

. "/data/adb/flux/scripts/lib"
. "/data/adb/flux/scripts/log"

readonly LOG_COMPONENT="Flux"

FLUXD_CHILD_PID=""
ADOPTED_FLUXD_PID=""
ADOPTED_FLUXD_START=""
WATCHDOG_LEASE_HELD=0
WATCHDOG_START_TICKS=""
WATCHDOG_BOOT_ID=""

_wait_for_boot() {
    local count=0
    while [ "${count}" -lt "${BOOT_TIMEOUT}" ]; do
        [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && return 0
        sleep 1
        count=$((count + 1))
    done
    return 1
}

_wait_for_fluxd_socket() {
    local pid="${1}"
    local count=0

    while [ "${count}" -lt "${FLUXD_SOCKET_READY_TIMEOUT}" ]; do
        _fluxd_child_running "${pid}" || return 1
        _fluxd_ready && return 0
        sleep 1
        count=$((count + 1))
    done
    return 1
}

_fluxd_ready() {
    [ -S "${FLUXD_SOCKET}" ] || return 1
    "${FLUXD_BIN}" ping >/dev/null 2>&1
}

_fluxd_child_running() {
    local pid="${1}"
    local state=""

    pid_alive "${pid}" || return 1
    state=$(awk '{ print $3 }' "/proc/${pid}/stat" 2>/dev/null || true)
    [ "${state}" != "Z" ]
}

_stop_fluxd_child() {
    local pid="${1}"
    local count=0

    _fluxd_child_running "${pid}" || return 0
    kill "${pid}" 2>/dev/null || true

    while [ "${count}" -lt "${FLUXD_SHUTDOWN_TIMEOUT}" ]; do
        _fluxd_child_running "${pid}" || return 0
        sleep 1
        count=$((count + 1))
    done

    _fluxd_child_running "${pid}" || return 0
    log_warn "fluxd did not stop, force killing (pid=${pid})"
    kill -9 "${pid}" 2>/dev/null || true
    return 0
}

_process_start_ticks() {
    process_start_ticks "${1}"
}

_current_boot_id() {
    current_boot_id
}

_read_watchdog_owner() {
    local owner_pid=""
    local owner_start=""
    local owner_boot_id=""
    local extra=""

    [ -f "${FLUXD_WATCHDOG_OWNER_FILE}" ] || return 1
    IFS=' ' read -r owner_pid owner_start owner_boot_id extra <"${FLUXD_WATCHDOG_OWNER_FILE}" || return 1
    is_int "${owner_pid}" || return 1
    is_int "${owner_start}" || return 1
    case "${owner_boot_id}" in
    '' | *[!0-9A-Fa-f-]*) return 1 ;;
    esac
    [ -z "${extra}" ] || return 1
    printf '%s %s %s\n' "${owner_pid}" "${owner_start}" "${owner_boot_id}"
}

_watchdog_owner_state() {
    local owner_pid="${1}"
    local owner_start="${2}"
    local owner_boot_id="${3}"
    local current_start=""
    local current_boot_id=""

    # Return 0 for the same live owner, 1 only for proven staleness, and 2
    # when procfs cannot establish either state safely.
    current_boot_id=$(_current_boot_id) || return 2
    [ "${current_boot_id}" = "${owner_boot_id}" ] || return 1
    pid_alive "${owner_pid}" || return 1
    current_start=$(_process_start_ticks "${owner_pid}") || return 2
    [ "${current_start}" = "${owner_start}" ] && return 0
    return 1
}

_create_watchdog_lease() {
    local start_ticks=""
    local boot_id=""

    mkdir "${FLUXD_WATCHDOG_LOCK_DIR}" 2>/dev/null || return 1
    start_ticks=$(_process_start_ticks "$$") || {
        rmdir "${FLUXD_WATCHDOG_LOCK_DIR}" 2>/dev/null || true
        return 1
    }
    boot_id=$(_current_boot_id) || {
        rmdir "${FLUXD_WATCHDOG_LOCK_DIR}" 2>/dev/null || true
        return 1
    }

    if ! atomic_write \
        "${FLUXD_WATCHDOG_OWNER_FILE}" \
        printf '%s %s %s\n' "$$" "${start_ticks}" "${boot_id}"; then
        rm -f "${FLUXD_WATCHDOG_OWNER_FILE}" 2>/dev/null || true
        rmdir "${FLUXD_WATCHDOG_LOCK_DIR}" 2>/dev/null || true
        return 1
    fi

    WATCHDOG_START_TICKS="${start_ticks}"
    WATCHDOG_BOOT_ID="${boot_id}"
    WATCHDOG_LEASE_HELD=1
    return 0
}

_reclaim_stale_watchdog_lease() {
    local expected_owner="${1}"

    (
        confirmed=""
        owner_state=0

        exec 9>"${FLUXD_WATCHDOG_REAP_FILE}" || exit 1
        if command -v flock >/dev/null 2>&1; then
            flock -n 9 || exit "${EX_TEMPFAIL}"
        elif command -v busybox >/dev/null 2>&1; then
            busybox flock -n 9 || exit "${EX_TEMPFAIL}"
        elif [ -x "/data/adb/magisk/busybox" ]; then
            /data/adb/magisk/busybox flock -n 9 || exit "${EX_TEMPFAIL}"
        elif [ -x "/data/adb/ksu/bin/busybox" ]; then
            /data/adb/ksu/bin/busybox flock -n 9 || exit "${EX_TEMPFAIL}"
        elif [ -x "/data/adb/ap/bin/busybox" ]; then
            /data/adb/ap/bin/busybox flock -n 9 || exit "${EX_TEMPFAIL}"
        else
            log_error "No verified flock applet is available for stale lease recovery"
            exit 1
        fi

        confirmed=$(_read_watchdog_owner 2>/dev/null || true)
        [ -n "${confirmed}" ] || exit 1
        [ "${confirmed}" = "${expected_owner}" ] || exit 1

        set -- ${confirmed}
        _watchdog_owner_state "${1}" "${2}" "${3}" || owner_state=$?
        [ "${owner_state}" -eq 1 ] || exit 1

        rm -rf "${FLUXD_WATCHDOG_LOCK_DIR}" 2>/dev/null || exit 1
    )
}

_acquire_watchdog_lease() {
    local attempt=0
    local owner=""
    local owner_pid=""
    local owner_start=""
    local owner_boot_id=""
    local owner_state=0

    while [ "${attempt}" -lt 3 ]; do
        _create_watchdog_lease && return 0

        owner=$(_read_watchdog_owner 2>/dev/null || true)
        if [ -z "${owner}" ]; then
            # The mkdir winner publishes its owner record immediately. Give a
            # concurrent winner time to do so before treating the lease as
            # abandoned after a dirty shutdown.
            sleep 1
            owner=$(_read_watchdog_owner 2>/dev/null || true)
            [ -n "${owner}" ] || {
                log_error "Watchdog lease owner is missing or malformed; refusing unsafe takeover"
                return 1
            }
        fi

        set -- ${owner}
        owner_pid="${1}"
        owner_start="${2}"
        owner_boot_id="${3}"
        owner_state=0
        _watchdog_owner_state "${owner_pid}" "${owner_start}" "${owner_boot_id}" || owner_state=$?
        if [ "${owner_state}" -eq 0 ]; then
            log_info "fluxd watchdog already running (pid=${owner_pid})"
            return "${EX_TEMPFAIL}"
        fi
        if [ "${owner_state}" -ne 1 ]; then
            log_error "Unable to validate watchdog lease owner safely"
            return 1
        fi

        # Serialize stale takeover with a kernel file lock, then revalidate the
        # complete owner identity while holding it. A missing/malformed owner
        # is deliberately fail-closed above because it cannot prove staleness.
        if ! _reclaim_stale_watchdog_lease "${owner}"; then
            attempt=$((attempt + 1))
            sleep 1
            continue
        fi

        attempt=$((attempt + 1))
    done

    log_error "Unable to acquire fluxd watchdog lease"
    return 1
}

_release_watchdog_lease() {
    local owner=""

    [ "${WATCHDOG_LEASE_HELD}" = "1" ] || return 0
    owner=$(_read_watchdog_owner 2>/dev/null || true)
    if [ "${owner}" = "$$ ${WATCHDOG_START_TICKS} ${WATCHDOG_BOOT_ID}" ]; then
        rm -f "${FLUXD_WATCHDOG_OWNER_FILE}" 2>/dev/null || true
        rmdir "${FLUXD_WATCHDOG_LOCK_DIR}" 2>/dev/null || true
    else
        log_warn "Watchdog lease ownership changed; leaving it intact"
    fi
    WATCHDOG_LEASE_HELD=0
    WATCHDOG_START_TICKS=""
    WATCHDOG_BOOT_ID=""
}

_clear_owned_fluxd_pid_file() {
    local child_pid="${1}"
    local recorded_pid=""

    recorded_pid=$(read_pid_file "${FLUXD_PID_FILE}" "fluxd" 2>/dev/null || true)
    [ "${recorded_pid}" = "${child_pid}" ] || return 0
    rm -f "${FLUXD_PID_FILE}" 2>/dev/null || true
}

_fluxd_identity_matches() {
    local pid="${1}"
    local expected_start="${2}"
    local current_start=""
    local state=""

    pid_alive "${pid}" || return 1
    current_start=$(_process_start_ticks "${pid}") || return 1
    [ "${current_start}" = "${expected_start}" ] || return 1
    pid_matches_cmd "${pid}" "${FLUXD_BIN}" || return 1
    state=$(awk '{ print $3 }' "/proc/${pid}/stat" 2>/dev/null || true)
    [ "${state}" != "Z" ]
}

_read_dispatch_owner() {
    local owner_pid=""
    local owner_start=""
    local owner_boot_id=""
    local extra=""

    [ -f "${DISPATCH_LOCK_OWNER_FILE}" ] || return 1
    IFS=' ' read -r owner_pid owner_start owner_boot_id extra <"${DISPATCH_LOCK_OWNER_FILE}" || return 1
    is_int "${owner_pid}" || return 1
    is_int "${owner_start}" || return 1
    case "${owner_boot_id}" in
    '' | *[!0-9A-Fa-f-]*) return 1 ;;
    esac
    [ -z "${extra}" ] || return 1
    printf '%s %s %s\n' "${owner_pid}" "${owner_start}" "${owner_boot_id}"
}

_dispatch_owner_state() {
    local owner_pid="${1}"
    local owner_start="${2}"
    local owner_boot_id="${3}"
    local current_start=""
    local current_boot_id=""

    current_boot_id=$(_current_boot_id) || return 2
    [ "${current_boot_id}" = "${owner_boot_id}" ] || return 1
    pid_alive "${owner_pid}" || return 1
    current_start=$(_process_start_ticks "${owner_pid}") || return 2
    [ "${current_start}" = "${owner_start}" ] || return 1
    pid_matches_cmd "${owner_pid}" "${DISPATCHER_SCRIPT}" || return 2
    return 0
}

_legacy_dispatcher_alive() {
    local pid=""

    command -v pgrep >/dev/null 2>&1 || return 2
    for pid in $(pgrep -f "${DISPATCHER_SCRIPT}" 2>/dev/null || true); do
        is_int "${pid}" || continue
        pid_alive "${pid}" || continue
        pid_matches_cmd "${pid}" "${DISPATCHER_SCRIPT}" && return 0
    done
    return 1
}

_recover_dispatch_lock() {
    local count=0
    local owner=""
    local state=0

    while [ -d "${DISPATCH_LOCK_DIR}" ] \
        && [ "${count}" -lt "${FLUXD_DISPATCH_RECOVERY_TIMEOUT}" ]; do
        owner=$(_read_dispatch_owner 2>/dev/null || true)
        if [ -n "${owner}" ]; then
            set -- ${owner}
            state=0
            _dispatch_owner_state "${1}" "${2}" "${3}" || state=$?
            case "${state}" in
            0)
                sleep 1
                count=$((count + 1))
                continue
                ;;
            1)
                rm -rf "${DISPATCH_LOCK_DIR}" 2>/dev/null || return 1
                return 0
                ;;
            *)
                log_error "Unable to validate active dispatcher lock safely"
                return 1
                ;;
            esac
        fi

        # Bridge releases predating owner records may leave an ownerless lock.
        # Wait once for an in-progress publisher, then remove it only when no
        # matching dispatcher process exists.
        sleep 1
        state=0
        _legacy_dispatcher_alive || state=$?
        case "${state}" in
        0)
            count=$((count + 1))
            ;;
        1)
            rm -rf "${DISPATCH_LOCK_DIR}" 2>/dev/null || return 1
            return 0
            ;;
        *)
            log_error "Cannot inspect ownerless dispatcher lock safely"
            return 1
            ;;
        esac
    done

    [ ! -d "${DISPATCH_LOCK_DIR}" ] && return 0
    log_error "Timed out waiting for active legacy dispatcher"
    return 1
}

_stop_adopted_fluxd() {
    local pid="${1}"
    local expected_start="${2}"
    local count=0

    _fluxd_identity_matches "${pid}" "${expected_start}" || return 0
    kill "${pid}" 2>/dev/null || true

    while [ "${count}" -lt "${FLUXD_SHUTDOWN_TIMEOUT}" ]; do
        _fluxd_identity_matches "${pid}" "${expected_start}" || return 0
        sleep 1
        count=$((count + 1))
    done

    _fluxd_identity_matches "${pid}" "${expected_start}" || return 0
    log_warn "Unready adopted fluxd did not stop, force killing (pid=${pid})"
    kill -9 "${pid}" 2>/dev/null || true

    count=0
    while [ "${count}" -lt 2 ]; do
        _fluxd_identity_matches "${pid}" "${expected_start}" || return 0
        sleep 1
        count=$((count + 1))
    done
    return 1
}

_watch_adopted_fluxd() {
    local pid="${1}"
    local expected_start=""
    local count=0

    expected_start=$(_process_start_ticks "${pid}") || {
        _clear_owned_fluxd_pid_file "${pid}"
        return 0
    }
    ADOPTED_FLUXD_PID="${pid}"
    ADOPTED_FLUXD_START="${expected_start}"

    while [ "${count}" -lt "${FLUXD_SOCKET_READY_TIMEOUT}" ]; do
        _fluxd_identity_matches "${pid}" "${expected_start}" || {
            _clear_owned_fluxd_pid_file "${pid}"
            ADOPTED_FLUXD_PID=""
            ADOPTED_FLUXD_START=""
            return 0
        }
        _fluxd_ready && break
        sleep 1
        count=$((count + 1))
    done

    if ! _fluxd_ready; then
        log_error "Adopted fluxd failed socket readiness (pid=${pid})"
        _stop_adopted_fluxd "${pid}" "${expected_start}" || return 1
        _clear_owned_fluxd_pid_file "${pid}"
        ADOPTED_FLUXD_PID=""
        ADOPTED_FLUXD_START=""
        return 0
    fi

    log_info "Adopted running fluxd (pid=${pid})"

    while _fluxd_identity_matches "${pid}" "${expected_start}"; do
        if ! _fluxd_ready; then
            log_error "Adopted fluxd lost socket readiness (pid=${pid})"
            _stop_adopted_fluxd "${pid}" "${expected_start}" || return 1
            break
        fi
        sleep 2
    done

    _clear_owned_fluxd_pid_file "${pid}"
    ADOPTED_FLUXD_PID=""
    ADOPTED_FLUXD_START=""
    return 0
}

_stop_children() {
    if [ -n "${FLUXD_CHILD_PID}" ]; then
        local child_pid="${FLUXD_CHILD_PID}"
        _stop_fluxd_child "${child_pid}"
        wait "${child_pid}" 2>/dev/null || true
        _clear_owned_fluxd_pid_file "${child_pid}"
        FLUXD_CHILD_PID=""
    fi

    if [ -n "${ADOPTED_FLUXD_PID}" ]; then
        _stop_adopted_fluxd "${ADOPTED_FLUXD_PID}" "${ADOPTED_FLUXD_START}" || true
        _clear_owned_fluxd_pid_file "${ADOPTED_FLUXD_PID}"
        ADOPTED_FLUXD_PID=""
        ADOPTED_FLUXD_START=""
    fi
}

_cleanup() {
    local rc=$?
    _stop_children
    _release_watchdog_lease
    return "${rc}"
}

_watch_fluxd() {
    local failures=0
    local backoff=1
    local started_at now lived rc

    while [ "${failures}" -lt "${FLUXD_RESTART_LIMIT}" ]; do
        started_at=$(date +%s)
        "${FLUXD_BIN}" daemon >>"${FLUXD_LOG_FILE}" 2>&1 &
        FLUXD_CHILD_PID=$!
        write_pid_file "${FLUXD_PID_FILE}" "${FLUXD_CHILD_PID}" || {
            local child_pid="${FLUXD_CHILD_PID}"
            _stop_fluxd_child "${child_pid}"
            wait "${child_pid}" 2>/dev/null || true
            _clear_owned_fluxd_pid_file "${child_pid}"
            FLUXD_CHILD_PID=""
            return 1
        }

        if ! _wait_for_fluxd_socket "${FLUXD_CHILD_PID}"; then
            log_error "fluxd did not create its control socket"
            _stop_fluxd_child "${FLUXD_CHILD_PID}"
        fi

        while _fluxd_child_running "${FLUXD_CHILD_PID}"; do
            if ! _fluxd_ready; then
                log_error "fluxd lost its control socket"
                _stop_fluxd_child "${FLUXD_CHILD_PID}"
                break
            fi
            sleep 2
        done

        if wait "${FLUXD_CHILD_PID}"; then
            rc=0
        else
            rc=$?
        fi
        _clear_owned_fluxd_pid_file "${FLUXD_CHILD_PID}"
        FLUXD_CHILD_PID=""

        now=$(date +%s)
        lived=$((now - started_at))
        if [ "${lived}" -ge "${FLUXD_RESTART_STABLE_SEC}" ]; then
            failures=0
            backoff=1
        else
            failures=$((failures + 1))
        fi

        [ "${failures}" -lt "${FLUXD_RESTART_LIMIT}" ] || {
            log_error "fluxd restart limit reached (last rc=${rc})"
            return 1
        }

        log_warn "fluxd exited (rc=${rc}); restarting in ${backoff}s"
        sleep "${backoff}"
        backoff=$((backoff * 2))
        [ "${backoff}" -le "${FLUXD_RESTART_BACKOFF_MAX}" ] || backoff="${FLUXD_RESTART_BACKOFF_MAX}"
    done

    return 1
}

main() {
    [ -d "${RUN_DIR}" ] || mkdir -p "${RUN_DIR}"
    [ -n "${FLUX_LOG}" ] && [ ! -t 2 ] && exec 2>>"${FLUX_LOG}"

    [ -x "${FLUXD_BIN}" ] || {
        log_error "fluxd binary missing or not executable: ${FLUXD_BIN}"
        return 1
    }

    trap 'exit 0' INT TERM
    trap '_cleanup' EXIT

    local lease_rc=0
    _acquire_watchdog_lease || lease_rc=$?
    if [ "${lease_rc}" -ne 0 ]; then
        [ "${lease_rc}" -eq "${EX_TEMPFAIL}" ] && return 0
        return "${lease_rc}"
    fi

    run "Wait for boot" _wait_for_boot || return 1

    local existing=""
    existing=$(read_pid_file "${FLUXD_PID_FILE}" "fluxd" 2>/dev/null || true)
    if [ -n "${existing}" ] \
        && pid_alive "${existing}" \
        && pid_matches_cmd "${existing}" "${FLUXD_BIN}"; then
        _watch_adopted_fluxd "${existing}" || return 1
    fi

    _recover_dispatch_lock || return 1

    _watch_fluxd
}

main "$@"
