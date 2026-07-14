#!/usr/bin/env sh

set -eu

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

skip_or_fail() {
    message="${1}"
    if [ "${FLUXCTL_STATUS_TESTS_REQUIRED}" = "1" ]; then
        fail "${message}"
    fi
    printf 'SKIP: %s\n' "${message}" >&2
    exit 0
}

if [ "${FLUXCTL_STATUS_STUB:-0}" = "1" ]; then
    : "${FLUXCTL_STATUS_RECORD:?missing status record path}"
    : "${FLUXCTL_STATUS_EXIT:?missing status exit code}"

    : >"${FLUXCTL_STATUS_RECORD}"
    for argument in "$@"; do
        printf '%s\n' "${argument}" >>"${FLUXCTL_STATUS_RECORD}"
    done
    printf '%s\n' "${FLUXCTL_STATUS_STDOUT:-}"
    printf '%s\n' "${FLUXCTL_STATUS_STDERR:-}" >&2
    exit "${FLUXCTL_STATUS_EXIT}"
fi

[ "$#" -eq 0 ] || fail "this wrapper does not accept arguments"

FLUXCTL_STATUS_TESTS_REQUIRED="${FLUXCTL_STATUS_TESTS_REQUIRED:-0}"
case "${FLUXCTL_STATUS_TESTS_REQUIRED}" in
0 | 1) ;;
*) fail "FLUXCTL_STATUS_TESTS_REQUIRED must be 0 or 1" ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) ||
    fail "cannot resolve the test directory"
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd -P) ||
    fail "cannot resolve the repository root"
readonly SCRIPT_DIR REPO_ROOT

BWRAP_COMMAND="${BWRAP:-bwrap}"
BWRAP_BIN=$(command -v "${BWRAP_COMMAND}" 2>/dev/null || true)
[ -n "${BWRAP_BIN}" ] ||
    skip_or_fail "bubblewrap is unavailable; install bubblewrap or set BWRAP"
[ -x "${BWRAP_BIN}" ] ||
    skip_or_fail "bubblewrap is not executable: ${BWRAP_BIN}"
readonly BWRAP_BIN

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM
mkdir -p "${tmp_dir}/hostile-cache"
: >"${tmp_dir}/hostile-cache/cache_valid"
printf 'exit 91\n' >"${tmp_dir}/hostile-cache/cache_config"

run_isolated() {
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
        --dir /data/adb/flux \
        --dir /data/adb/flux/bin \
        --ro-bind "${tmp_dir}/hostile-cache" /data/adb/flux/cache \
        --ro-bind "${REPO_ROOT}/scripts" /data/adb/flux/scripts \
        --ro-bind "${SCRIPT_DIR}/run-fluxctl-tests.sh" /data/adb/flux/bin/fluxd \
        --bind "${tmp_dir}" /test-output \
        --setenv FLUXCTL_STATUS_STUB 1 \
        --setenv FLUXCTL_STATUS_RECORD /test-output/argv \
        --setenv FLUXCTL_STATUS_EXIT "${FLUXCTL_STATUS_EXIT}" \
        --setenv FLUXCTL_STATUS_STDOUT "${FLUXCTL_STATUS_STDOUT}" \
        --setenv FLUXCTL_STATUS_STDERR "${FLUXCTL_STATUS_STDERR}" \
        /usr/bin/sh /data/adb/flux/scripts/fluxctl "$@"
}

if ! "${BWRAP_BIN}" \
    --tmpfs / \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --proc /proc \
    --dev /dev \
    /usr/bin/true 2>/dev/null; then
    skip_or_fail "bubblewrap namespaces are not permitted by this host"
fi

assert_file() {
    expected="${1}"
    path="${2}"
    label="${3}"
    actual=$(cat "${path}")
    [ "${actual}" = "${expected}" ] || {
        printf '%s\n' '--- expected ---' >&2
        printf '%s\n' "${expected}" >&2
        printf '%s\n' '--- actual ---' >&2
        printf '%s\n' "${actual}" >&2
        fail "${label}"
    }
}

FLUXCTL_STATUS_EXIT=0
FLUXCTL_STATUS_STDOUT='authoritative text status'
FLUXCTL_STATUS_STDERR='text diagnostic'
export FLUXCTL_STATUS_EXIT FLUXCTL_STATUS_STDOUT FLUXCTL_STATUS_STDERR
run_isolated status >"${tmp_dir}/stdout" 2>"${tmp_dir}/stderr"
assert_file 'status' "${tmp_dir}/argv" "text status arguments changed"
assert_file 'authoritative text status' "${tmp_dir}/stdout" "text status output changed"
assert_file 'text diagnostic' "${tmp_dir}/stderr" "text status stderr changed"

FLUXCTL_STATUS_EXIT=23
FLUXCTL_STATUS_STDOUT='authoritative json status'
FLUXCTL_STATUS_STDERR='json diagnostic'
export FLUXCTL_STATUS_EXIT FLUXCTL_STATUS_STDOUT FLUXCTL_STATUS_STDERR
set +e
run_isolated status --json >"${tmp_dir}/stdout" 2>"${tmp_dir}/stderr"
status_exit=$?
set -e
[ "${status_exit}" -eq 23 ] ||
    fail "JSON status exit changed: expected 23, found ${status_exit}"
assert_file 'status
--json' "${tmp_dir}/argv" "JSON status arguments changed"
assert_file 'authoritative json status' "${tmp_dir}/stdout" "JSON status output changed"
assert_file 'json diagnostic' "${tmp_dir}/stderr" "JSON status stderr changed"

printf 'fluxctl status shell tests: PASS\n'
