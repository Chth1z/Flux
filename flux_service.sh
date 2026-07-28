#!/system/bin/sh

# Bounded module-local launcher. fluxd owns runtime and recovery policy.
set -u

readonly BOOT_WAIT_LIMIT=180
readonly RESTART_LIMIT=5
readonly RESTART_BACKOFF_MAX=16

FLUXD_CHILD_PID=""
STOP_REQUESTED=0

stop_fluxd_child() {
    STOP_REQUESTED=1
    [ -z "${FLUXD_CHILD_PID}" ] || kill "${FLUXD_CHILD_PID}" 2>/dev/null || true
}

trap stop_fluxd_child INT TERM

boot_wait=0
while ! getprop sys.boot_completed 2>/dev/null | grep -qx '1'; do
    [ "${boot_wait}" -lt "${BOOT_WAIT_LIMIT}" ] || exit 1
    sleep 1
    boot_wait=$((boot_wait + 1))
done

[ -x /data/adb/flux/bin/fluxd ] || exit 1

attempt=0
backoff=1
last_rc=1
while [ "${attempt}" -lt "${RESTART_LIMIT}" ]; do
    /data/adb/flux/bin/fluxd daemon &
    FLUXD_CHILD_PID=$!
    if wait "${FLUXD_CHILD_PID}"; then
        last_rc=0
    else
        last_rc=$?
    fi
    FLUXD_CHILD_PID=""

    [ "${STOP_REQUESTED}" -eq 0 ] || exit 0
    [ "${last_rc}" -ne 0 ] || exit 0

    attempt=$((attempt + 1))
    [ "${attempt}" -lt "${RESTART_LIMIT}" ] || break
    sleep "${backoff}"
    backoff=$((backoff * 2))
    [ "${backoff}" -le "${RESTART_BACKOFF_MAX}" ] || backoff="${RESTART_BACKOFF_MAX}"
done

exit "${last_rc}"
