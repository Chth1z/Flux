#!/bin/ash

set -eu

readonly BUSYBOX=/bin/busybox
readonly WORKSPACE="${ORACLE_WORKSPACE:-/workspace}"

export LANG=C
export LC_ALL=C
export TZ=UTC
umask 077

# Force every external command used by scripts/rules through the exact BusyBox
# binary pinned by manifest.json. The shell itself is launched as the same
# binary's ash applet by the outer read-only container runner.
awk() {
    "${BUSYBOX}" awk "$@"
}

cat() {
    "${BUSYBOX}" cat "$@"
}

probe_environment() {
    local hash version
    hash=$("${BUSYBOX}" sha256sum "${BUSYBOX}")
    hash=${hash%% *}
    version=$("${BUSYBOX}" 2>&1 | "${BUSYBOX}" sed -n '1p')
    printf 'busybox_sha256=%s\nbusybox_version=%s\n' "${hash}" "${version}"
}

[ "$#" -eq 1 ] || {
    printf 'usage: generate.sh {probe|maximal-zone-v1-{ipv4,ipv6}-{apply,cleanup}}\n' >&2
    exit 2
}

case "$1" in
probe)
    probe_environment
    exit 0
    ;;
maximal-zone-v1-ipv4-apply|maximal-zone-v1-ipv4-cleanup|maximal-zone-v1-ipv6-apply|maximal-zone-v1-ipv6-cleanup) ;;
*)
    printf 'unknown xtables oracle fixture: %s\n' "$1" >&2
    exit 2
    ;;
esac

. "${WORKSPACE}/tests/oracle/xtables/maximal-zone-v1.env"
. "${WORKSPACE}/scripts/rules"

case "$1" in
maximal-zone-v1-ipv4-apply) action=-A family=4 ;;
maximal-zone-v1-ipv4-cleanup) action=-D family=4 ;;
maximal-zone-v1-ipv6-apply) action=-A family=6 ;;
maximal-zone-v1-ipv6-cleanup) action=-D family=6 ;;
esac

# scripts/init reaches generate through atomic_write's conditional command.
# Keep the same errexit context so optional false predicates inside the frozen
# oracle do not terminate a successful generation early.
if generate "${action}" "${family}"; then
    exit 0
else
    rc=$?
    printf 'xtables oracle generation failed (rc=%s)\n' "${rc}" >&2
    exit "${rc}"
fi
