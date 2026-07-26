#!/system/bin/sh

# Module glue only: Rust owns both the online stop transition and offline
# recovery. This script never reads ownership records or mutates networking.
set -u

readonly FLUXD_BIN="/data/adb/flux/bin/fluxd"

# An already-removed payload has nothing left to invoke. The next boot will
# provide the normal kernel reset boundary.
[ -x "${FLUXD_BIN}" ] || exit 0

# Let the live daemon serialize its own stop/recovery while its lease is held.
if "${FLUXD_BIN}" ping >/dev/null 2>&1; then
    if "${FLUXD_BIN}" stop; then
        exit 0
    fi
fi

# If no daemon answers, Rust's kernel lease and durable ownership records decide
# whether bounded offline cleanup may proceed.
exec "${FLUXD_BIN}" cleanup --offline
