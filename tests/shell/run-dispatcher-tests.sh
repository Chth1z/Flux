#!/usr/bin/env sh

set -eu

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

skip_or_fail() {
    message="${1}"
    if [ "${FLUX_DISPATCHER_TESTS_REQUIRED}" = "1" ]; then
        fail "${message}"
    fi
    printf 'SKIP: %s\n' "${message}" >&2
    exit 0
}

[ "$#" -eq 0 ] || fail "this wrapper does not accept arguments"

FLUX_DISPATCHER_TESTS_REQUIRED="${FLUX_DISPATCHER_TESTS_REQUIRED:-0}"
case "${FLUX_DISPATCHER_TESTS_REQUIRED}" in
0 | 1) ;;
*) fail "FLUX_DISPATCHER_TESTS_REQUIRED must be 0 or 1" ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) ||
    fail "cannot resolve the wrapper directory"
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd -P) ||
    fail "cannot resolve the repository root"
readonly SCRIPT_DIR REPO_ROOT

[ -f "${REPO_ROOT}/tests/shell/dispatcher_fluxd_mode.sh" ] ||
    fail "dispatcher bridge suite is missing from ${REPO_ROOT}"
[ -f "${REPO_ROOT}/scripts/dispatcher" ] ||
    fail "repository root does not contain scripts/dispatcher: ${REPO_ROOT}"

BWRAP_COMMAND="${BWRAP:-bwrap}"
BWRAP_BIN=$(command -v "${BWRAP_COMMAND}" 2>/dev/null || true)
[ -n "${BWRAP_BIN}" ] ||
    skip_or_fail "bubblewrap is unavailable; install the bubblewrap package or set BWRAP"
[ -x "${BWRAP_BIN}" ] ||
    skip_or_fail "bubblewrap is not executable: ${BWRAP_BIN}"
readonly BWRAP_BIN

run_bwrap() {
    "${BWRAP_BIN}" \
        --tmpfs / \
        --ro-bind /usr /usr \
        --ro-bind /etc /etc \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --dir /tmp \
        --dir /data \
        --dir /data/adb \
        --dir /data/adb/modules \
        --dir /data/adb/magisk \
        --ro-bind "${REPO_ROOT}" /src \
        "$@"
}

# Probe the same namespace and mount topology before launching the suite. This
# distinguishes a host that forbids bubblewrap namespaces from a real test
# failure. CI sets FLUX_DISPATCHER_TESTS_REQUIRED=1 so either condition fails.
if ! run_bwrap /usr/bin/true 2>/dev/null; then
    skip_or_fail "bubblewrap namespaces are not permitted by this host"
fi

run_bwrap /usr/bin/sh /src/tests/shell/dispatcher_fluxd_mode.sh
