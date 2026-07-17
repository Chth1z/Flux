#!/usr/bin/sh

set -eu

readonly FLUX_ROOT="/data/adb/flux"
readonly RUN_ROOT="${FLUX_ROOT}/run"
readonly GENERATIONS_ROOT="${RUN_ROOT}/generations"
readonly CALLS_FILE="${RUN_ROOT}/test-calls"
readonly ENV_CALLS_FILE="${RUN_ROOT}/test-env-calls"
readonly DISPATCHER="${FLUX_ROOT}/scripts/dispatcher"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_file_equals() {
    local expected="${1}"
    local actual="${2}"

    cmp -s "${expected}" "${actual}" || {
        printf '%s\n' '--- expected ---' >&2
        cat "${expected}" >&2
        printf '%s\n' '--- actual ---' >&2
        [ -f "${actual}" ] && cat "${actual}" >&2 || printf '<missing>\n' >&2
        fail "${actual} did not match"
    }
}

assert_not_called() {
    local component="${1}"
    [ ! -f "${CALLS_FILE}" ] || ! grep -q "^${component}:" "${CALLS_FILE}" ||
        fail "${component} must not be invoked"
}

manifest_value() {
    local name="${1}"
    local manifest="${2:-${RUN_ROOT}/engine.manifest}"

    sed -n "s/^${name}=//p" "${manifest}"
}

process_start_ticks_for_test() {
    sh -c '. /src/scripts/lib; process_start_ticks "$1"' sh "${1}"
}

write_shell_xtables_writer_owner() {
    local parent_pid="${1}"
    local parent_start_ticks="${2}"
    local child_pid="${3}"
    local child_start_ticks="${4}"
    local boot_id="${5}"

    mkdir -p "${RUN_ROOT}/xtables-writer.lock"
    printf 'flux-shell-xtables-writer-owner-v2 %s %s %s %s %s\n' \
        "${parent_pid}" "${parent_start_ticks}" \
        "${child_pid}" "${child_start_ticks}" "${boot_id}" \
        >"${RUN_ROOT}/xtables-writer.lock/shell-owner"
}

assert_shell_xtables_writer_parent_only() {
    local parent_pid="${1}"
    local parent_start_ticks="${2}"
    local boot_id="${3}"

    grep -qx \
        "flux-shell-xtables-writer-owner-v2 ${parent_pid} ${parent_start_ticks} 0 0 ${boot_id}" \
        "${RUN_ROOT}/xtables-writer.lock/shell-owner" ||
        fail "shell writer record did not retain only its live parent"
}

wait_for_test_file() {
    local path="${1}"
    local label="${2}"
    local attempts=0

    while [ ! -e "${path}" ] && [ "${attempts}" -lt 500 ]; do
        sleep 0.01
        attempts=$((attempts + 1))
    done
    [ -e "${path}" ] || fail "timed out waiting for ${label}"
}

wait_for_test_pid_dead() {
    local pid="${1}"
    local label="${2}"
    local attempts=0

    while [ -e "/proc/${pid}" ] && [ "${attempts}" -lt 500 ]; do
        sleep 0.01
        attempts=$((attempts + 1))
    done
    [ ! -e "/proc/${pid}" ] || fail "timed out waiting for ${label} to exit"
}

start_shell_xtables_writer_pair() {
    cat >"${RUN_ROOT}/writer-child.sh" <<'EOF'
#!/usr/bin/sh
set -eu
. /src/scripts/lib

inherit_shell_xtables_writer_lock || {
    : >/data/adb/flux/run/writer-child-inherit-failed
    exit 81
}
printf '%s\n' "$$" >/data/adb/flux/run/writer-child-pid
: >/data/adb/flux/run/writer-child-ready
while [ ! -e /data/adb/flux/run/writer-child-release ]; do
    sleep 0.01
done
release_shell_xtables_writer_lock || exit 82
: >/data/adb/flux/run/writer-child-released
EOF
    cat >"${RUN_ROOT}/writer-parent.sh" <<'EOF'
#!/usr/bin/sh
set -eu
. /src/scripts/lib

claim_shell_xtables_writer_lock || exit 83
printf '%s\n' "$$" >/data/adb/flux/run/writer-parent-pid
: >/data/adb/flux/run/writer-parent-ready
FLUX_XTABLES_WRITER_OWNER_PID="${XTABLES_WRITER_OWNER_PID}" \
    FLUX_XTABLES_WRITER_OWNER_START_TICKS="${XTABLES_WRITER_OWNER_START_TICKS}" \
    FLUX_XTABLES_WRITER_OWNER_BOOT_ID="${XTABLES_WRITER_OWNER_BOOT_ID}" \
    sh /data/adb/flux/run/writer-child.sh &
child_pid=$!
wait "${child_pid}" || true
: >/data/adb/flux/run/writer-child-finished
while [ ! -e /data/adb/flux/run/writer-parent-release ]; do
    sleep 0.01
done
release_shell_xtables_writer_lock || exit 84
: >/data/adb/flux/run/writer-parent-released
EOF
    chmod 0755 "${RUN_ROOT}/writer-child.sh" "${RUN_ROOT}/writer-parent.sh"

    sh "${RUN_ROOT}/writer-parent.sh" &
    WRITER_PARENT_PID=$!
    wait_for_test_file "${RUN_ROOT}/writer-parent-ready" "writer parent claim"
    wait_for_test_file "${RUN_ROOT}/writer-child-ready" "writer child inheritance"
    WRITER_CHILD_PID=$(cat "${RUN_ROOT}/writer-child-pid")
    [ "$(cat "${RUN_ROOT}/writer-parent-pid")" = "${WRITER_PARENT_PID}" ] ||
        fail "writer parent pid evidence did not match the launched process"
}

assert_direct_tproxy_writer_blocked() {
    local output="${1}"
    local label="${2}"

    if sh /src/scripts/tproxy invalid >"${output}" 2>&1; then
        fail "${label} unexpectedly crossed the shell writer lock"
    fi
    grep -q 'Another xtables ownership transition is in progress' "${output}" ||
        fail "${label} was not classified as a live shell writer"
}

assert_direct_tproxy_writer_recovered() {
    local output="${1}"
    local label="${2}"

    if sh /src/scripts/tproxy invalid >"${output}" 2>&1; then
        fail "invalid tproxy action unexpectedly succeeded after ${label}"
    fi
    grep -q '^Usage:' "${output}" ||
        fail "direct tproxy did not recover ${label}"
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "direct tproxy retained the recovered ${label}"
}

prepare_generation() {
    run_bridge prepare || fail "prepare verb failed"
    manifest_value generation
}

write_stub() {
    local name="${1}"
    local body="${2}"
    local target="${FLUX_ROOT}/scripts/${name}"

    {
        printf '%s\n' '#!/usr/bin/sh' 'set -eu'
        printf '%s\n' "${body}"
    } >"${target}"
    chmod 0755 "${target}"
}

reset_fixture() {
    [ ! -d "${FLUX_ROOT}" ] || chmod -R u+w "${FLUX_ROOT}" 2>/dev/null || true
    rm -rf "${FLUX_ROOT}" /data/adb/modules/flux /data/adb/magisk
    mkdir -p \
        "${FLUX_ROOT}/bin" \
        "${FLUX_ROOT}/cache" \
        "${FLUX_ROOT}/conf" \
        "${RUN_ROOT}" \
        "${FLUX_ROOT}/scripts" \
        "${FLUX_ROOT}/state" \
        /data/adb/modules/flux \
        /data/adb/magisk

    cp /src/scripts/dispatcher /src/scripts/lib /src/scripts/log "${FLUX_ROOT}/scripts/"
    chmod 0755 "${DISPATCHER}"

    cat >"${FLUX_ROOT}/cache/cache_config" <<'EOF'
LOG_LEVEL=0
LOG_MAX_SIZE=1048576
CORE_USER=root
CORE_GROUP=root
CORE_TIMEOUT=5
PROXY_MODE=tproxy
PROXY_PORT=1536
PROXY_IPV6=0
KFEAT_OWNER=1
TUN_INTERFACE=tun0
EOF
    printf '*mangle\nCOMMIT\n' >"${FLUX_ROOT}/cache/cache_rules_ipv4"
    printf '*mangle\nCOMMIT\n' >"${FLUX_ROOT}/cache/cache_cleanup_ipv4"
    : >"${FLUX_ROOT}/cache/cache_packages"
    printf 'rust\n' >"${FLUX_ROOT}/cache/cache_valid"
    write_stub config '
_process_settings() {
    cat /data/adb/flux/cache/cache_config
}
_detect_kernel() {
    return 0
}'
    : >"${FLUX_ROOT}/conf/settings.ini"
    printf '{}\n' >"${FLUX_ROOT}/conf/config.json"
    printf 'description=Flux shell test\n' >/data/adb/modules/flux/module.prop
    printf '#!/usr/bin/sh\nexit 0\n' >"${FLUX_ROOT}/bin/sing-box"
    chmod 0755 "${FLUX_ROOT}/bin/sing-box"

    write_stub init '
printf "init:%s\n" "$*" >>/data/adb/flux/run/test-calls
[ ! -f /data/adb/flux/run/fail-init ] || exit 41
if [ "${FLUXD_ENGINE_OWNER:-legacy}" = rust ]; then
    printf "FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n" "${FLUX_GENERATION_ID:?missing generation}" >/data/adb/flux/cache/cache_rules_manifest
fi
: >/data/adb/flux/cache/cache_valid
exit 0'
    write_stub core '
printf "core:%s\n" "$*" >>/data/adb/flux/run/test-calls
exit 0'
    write_stub addrsync '
. /data/adb/flux/scripts/lib
if [ -n "${FLUX_XTABLES_WRITER_OWNER_PID:-}" ] ||
    [ -n "${FLUX_XTABLES_WRITER_OWNER_START_TICKS:-}" ] ||
    [ -n "${FLUX_XTABLES_WRITER_OWNER_BOOT_ID:-}" ]; then
    inherit_shell_xtables_writer_lock || exit 90
    trap '\''release_shell_xtables_writer_lock'\'' EXIT
    trap '\''exit 130'\'' INT
    trap '\''exit 143'\'' TERM
fi
printf "addrsync:%s\n" "$*" >>/data/adb/flux/run/test-calls
printf "addrsync:%s:generation=%s:port=%s\n" "$*" "${FLUX_GENERATION_ID:-none}" "${PROXY_PORT:-none}" >>/data/adb/flux/run/test-env-calls
exit 0'
    write_stub tproxy '
. /data/adb/flux/scripts/lib
if [ -n "${FLUX_XTABLES_WRITER_OWNER_PID:-}" ] ||
    [ -n "${FLUX_XTABLES_WRITER_OWNER_START_TICKS:-}" ] ||
    [ -n "${FLUX_XTABLES_WRITER_OWNER_BOOT_ID:-}" ]; then
    inherit_shell_xtables_writer_lock || exit 90
    trap '\''release_shell_xtables_writer_lock'\'' EXIT
    trap '\''exit 130'\'' INT
    trap '\''exit 143'\'' TERM
fi
printf "tproxy:%s\n" "$*" >>/data/adb/flux/run/test-calls
printf "tproxy:%s:generation=%s:port=%s:cache=%s\n" "$*" "${FLUX_GENERATION_ID:-none}" "${PROXY_PORT:-none}" "${CACHE_RULES_V4_FILE:-none}" >>/data/adb/flux/run/test-env-calls
[ "${1:-}" != start ] || [ ! -f /data/adb/flux/run/fail-tproxy-start ] || exit 42
if [ "${1:-}" = start ]; then
    printf "PROXY_MODE=%s\n" "${PROXY_MODE:-tproxy}" >/data/adb/flux/run/active_runtime
    printf "cleanup\n" >/data/adb/flux/run/active_cleanup_ipv4
elif [ "${1:-}" = stop ]; then
    rm -f /data/adb/flux/run/active_runtime /data/adb/flux/run/active_cleanup_ipv4
fi
    exit 0'
}

install_real_init_fixture() {
    printf 'UPDATE_INTERVAL=0\n' >>"${FLUX_ROOT}/cache/cache_config"
    cp /src/scripts/init "${FLUX_ROOT}/scripts/init"
    chmod 0755 "${FLUX_ROOT}/scripts/init"
    cat >"${FLUX_ROOT}/scripts/config" <<'EOF'
_process_settings() {
    cat /data/adb/flux/cache/cache_config
}

_detect_kernel() {
    return 0
}

build_config() {
    cat <<'CONFIG'
LOG_LEVEL='0'
LOG_MAX_SIZE='1048576'
UPDATE_INTERVAL='0'
CORE_USER='root'
CORE_GROUP='root'
CORE_TIMEOUT='5'
PROXY_MODE='tproxy'
PROXY_PORT='1536'
PROXY_IPV6='0'
APP_PROXY_MODE='2'
APP_LIST='com.example.alpha'
KFEAT_OWNER=1
CONFIG
}
EOF
    write_stub updater.sh 'exit 0'
    write_stub fluxctl 'exit 0'
    for binary in jq addrsyncd; do
        printf '#!/usr/bin/sh\nexit 0\n' >"${FLUX_ROOT}/bin/${binary}"
        chmod 0755 "${FLUX_ROOT}/bin/${binary}"
    done
    : >"${FLUX_ROOT}/conf/addrsyncd.toml"
    printf '{}\n' >"${FLUX_ROOT}/conf/template.json"
    mkdir -p /data/system
    cat >/data/system/packages.list <<'EOF'
com.example.alpha 10124 0 /data/user/0/com.example.alpha default 3003,3002 0 1
EOF
}

run_bridge() {
    FLUXD_BRIDGE=1 sh "${DISPATCHER}" "$@"
}

test_prepare_writes_exact_direct_manifest_without_core() {
    reset_fixture

    generation=$(prepare_generation)
    [ "${generation}" = "1" ] || fail "first generation must be 1"

    cat >"${RUN_ROOT}/expected-manifest" <<'EOF'
FLUX_ENGINE_MANIFEST_V1
generation=1
binary=/data/adb/flux/bin/sing-box
config=/data/adb/flux/run/generations/1/config.json
working_directory=/data/adb/flux/run
log=/data/adb/flux/run/generations/1/sing-box.log
launcher=direct
readiness=listener
startup_timeout_ms=5000
stop_timeout_ms=5000
listener_port=1536
EOF
    assert_file_equals "${RUN_ROOT}/expected-manifest" "${RUN_ROOT}/engine.manifest"
    assert_file_equals "${RUN_ROOT}/engine.manifest" "${GENERATIONS_ROOT}/1/engine.manifest"
    assert_file_equals "${FLUX_ROOT}/conf/config.json" "${GENERATIONS_ROOT}/1/config.json"
    assert_file_equals "${FLUX_ROOT}/cache/cache_config" "${GENERATIONS_ROOT}/1/cache_config"
    assert_file_equals "${FLUX_ROOT}/cache/cache_packages" "${GENERATIONS_ROOT}/1/cache_packages"
    grep -qx 'generation=1' "${GENERATIONS_ROOT}/1/legacy-rules.manifest" ||
        fail "Generation did not retain its bound legacy rules manifest"
    [ "$(stat -c '%a' "${GENERATIONS_ROOT}/1")" = "555" ] ||
        fail "completed generation directory is mutable"
    [ "$(stat -c '%a' "${GENERATIONS_ROOT}/1/config.json")" = "444" ] ||
        fail "generation config snapshot is mutable"
    [ "$(stat -c '%a' "${GENERATIONS_ROOT}/1/cache_config")" = "444" ] ||
        fail "generation environment snapshot is mutable"
    grep -qx 'init:init' "${CALLS_FILE}" || fail "prepare must run init/config generation"
    assert_not_called core
}

test_real_init_uses_rust_renderer_and_snapshots_one_package_inventory() {
    reset_fixture
    install_real_init_fixture
    cat >"${FLUX_ROOT}/bin/sing-box" <<'EOF'
#!/usr/bin/sh
printf 'sing-box:%s\n' "$*" >>/data/adb/flux/run/test-calls
exit 77
EOF
    chmod 0755 "${FLUX_ROOT}/bin/sing-box"
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
if [ "${1:-}" = snapshot-legacy-packages ]; then
    printf 'rust-snapshot:%s\n' "$*" >>/data/adb/flux/run/test-calls
    cat "${3}"
    exit 0
fi
if [ "${1:-}" = attest-legacy-rules-set ]; then
    printf 'rust-attest:%s\n' "$*" >>/data/adb/flux/run/test-calls
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n' "${3}"
    exit 0
fi
printf 'rust-render:%s\n' "$*" >>/data/adb/flux/run/test-calls
printf '*mangle\nCOMMIT\n'
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"

    generation=$(prepare_generation)

    grep -qx 'rust-render:render-legacy-rules --packages-list /data/adb/flux/cache/cache_packages --family 4 --action apply' "${CALLS_FILE}" ||
        fail "real init did not invoke the Rust IPv4 apply renderer"
    grep -qx 'rust-render:render-legacy-rules --packages-list /data/adb/flux/cache/cache_packages --family 4 --action cleanup' "${CALLS_FILE}" ||
        fail "real init did not invoke the Rust IPv4 cleanup renderer"
    grep -qx 'rust-snapshot:snapshot-legacy-packages --source /data/system/packages.list' "${CALLS_FILE}" ||
        fail "real init did not invoke the bounded Rust package snapshot helper"
    grep -qx "rust-attest:attest-legacy-rules-set --generation ${generation} --packages-list /data/adb/flux/cache/cache_packages --ipv4-apply /data/adb/flux/cache/cache_rules_ipv4 --ipv4-cleanup /data/adb/flux/cache/cache_cleanup_ipv4" "${CALLS_FILE}" ||
        fail "real init did not attest the complete staged IPv4 rule set"
    assert_not_called sing-box
    [ "$(grep -c '^rust-render:' "${CALLS_FILE}")" -eq 2 ] ||
        fail "real init invoked an unexpected renderer count"
    assert_file_equals /data/system/packages.list "${GENERATIONS_ROOT}/${generation}/cache_packages"
    grep -qx '\*mangle' "${GENERATIONS_ROOT}/${generation}/cache_rules_ipv4" ||
        fail "generation did not retain Rust-rendered apply bytes"
    grep -qx '\*mangle' "${GENERATIONS_ROOT}/${generation}/cache_cleanup_ipv4" ||
        fail "generation did not retain Rust-rendered cleanup bytes"
    grep -qx "generation=${generation}" "${GENERATIONS_ROOT}/${generation}/legacy-rules.manifest" ||
        fail "generation did not retain its Rust artifact receipt"
    assert_not_called core
}

test_real_init_attests_and_snapshots_one_dual_family_rule_set() {
    reset_fixture
    install_real_init_fixture
    sed -i "s/PROXY_IPV6='0'/PROXY_IPV6='1'/" "${FLUX_ROOT}/scripts/config"
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
case "${1:-}" in
snapshot-legacy-packages)
    cat "${3}"
    ;;
render-legacy-rules)
    printf 'rust-render:%s\n' "$*" >>/data/adb/flux/run/test-calls
    printf '*mangle\nCOMMIT\n'
    ;;
attest-legacy-rules-set)
    printf 'rust-attest:%s\n' "$*" >>/data/adb/flux/run/test-calls
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4,ipv6\n' "${3}"
    ;;
*) exit 2 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"

    generation=$(prepare_generation)

    [ "$(grep -c '^rust-render:' "${CALLS_FILE}")" -eq 4 ] ||
        fail "dual-family preparation did not render exactly four artifacts"
    grep -qx "rust-attest:attest-legacy-rules-set --generation ${generation} --packages-list /data/adb/flux/cache/cache_packages --ipv4-apply /data/adb/flux/cache/cache_rules_ipv4 --ipv4-cleanup /data/adb/flux/cache/cache_cleanup_ipv4 --ipv6-apply /data/adb/flux/cache/cache_rules_ipv6 --ipv6-cleanup /data/adb/flux/cache/cache_cleanup_ipv6" "${CALLS_FILE}" ||
        fail "real init did not attest the complete staged dual-family rule set"
    [ -s "${GENERATIONS_ROOT}/${generation}/cache_rules_ipv6" ] ||
        fail "dual-family generation did not retain IPv6 apply bytes"
    [ -s "${GENERATIONS_ROOT}/${generation}/cache_cleanup_ipv6" ] ||
        fail "dual-family generation did not retain IPv6 cleanup bytes"
    grep -qx 'families=ipv4,ipv6' "${GENERATIONS_ROOT}/${generation}/legacy-rules.manifest" ||
        fail "dual-family generation did not retain its family-bound receipt"
    assert_not_called core
}

test_real_init_rebuilds_before_reusing_a_stale_generation_receipt() {
    reset_fixture
    install_real_init_fixture
    sed -i '/^build_config() {/a\    [ ! -e /data/adb/flux/cache/cache_rules_manifest ] || exit 88' "${FLUX_ROOT}/scripts/config"
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
case "${1:-}" in
snapshot-legacy-packages)
    cat "${3}"
    ;;
render-legacy-rules)
    printf '*mangle\nCOMMIT\n'
    ;;
attest-legacy-rules-set)
    printf 'rust-attest:%s\n' "$*" >>/data/adb/flux/run/test-calls
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n' "${3}"
    ;;
*) exit 2 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=1\nfamilies=ipv4\n' >"${FLUX_ROOT}/cache/cache_rules_manifest"
    printf 'rust\n' >"${FLUX_ROOT}/cache/cache_valid"

    FLUX_CACHE_BUILD_SERIALIZED=1 FLUXD_ENGINE_OWNER=rust FLUX_GENERATION_ID=2 sh -c '
        set -a
        . /data/adb/flux/cache/cache_config
        set +a
        sh /data/adb/flux/scripts/init init
    ' ||
        fail "real init did not rebuild a cache with a stale Generation receipt"

    grep -qx 'rust-attest:attest-legacy-rules-set --generation 2 --packages-list /data/adb/flux/cache/cache_packages --ipv4-apply /data/adb/flux/cache/cache_rules_ipv4 --ipv4-cleanup /data/adb/flux/cache/cache_cleanup_ipv4' "${CALLS_FILE}" ||
        fail "real init reused the stale receipt instead of re-attesting Generation 2"
    grep -qx 'generation=2' "${FLUX_ROOT}/cache/cache_rules_manifest" ||
        fail "real init did not replace the stale receipt"
}

test_serialized_cache_preview_bootstraps_without_a_generation_receipt() {
    reset_fixture
    install_real_init_fixture
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
case "${1:-}" in
snapshot-legacy-packages)
    cat "${3}"
    ;;
render-legacy-rules)
    printf 'preview-render:%s\n' "$*" >>/data/adb/flux/run/test-calls
    printf '*mangle\nCOMMIT\n'
    ;;
attest-legacy-rules-set)
    printf 'preview-attest:%s\n' "$*" >>/data/adb/flux/run/test-calls
    exit 97
    ;;
*) exit 2 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"
    printf 'stale-receipt\n' >"${FLUX_ROOT}/cache/cache_rules_manifest"

    if FLUXD_ENGINE_OWNER=rust sh "${FLUX_ROOT}/scripts/init" cache; then
        fail "direct cache preview bypassed dispatcher serialization"
    fi
    run_bridge cache-preview ||
        fail "serialized cache preview did not bootstrap without exported config"

    [ "$(grep -c '^preview-render:' "${CALLS_FILE}")" -eq 2 ] ||
        fail "direct cache preview did not render the IPv4 pair"
    ! grep -q '^preview-attest:' "${CALLS_FILE}" ||
        fail "non-Generation cache preview invoked the attester"
    [ ! -e "${FLUX_ROOT}/cache/cache_rules_manifest" ] ||
        fail "non-Generation cache preview retained a misleading receipt"
    [ "$(cat "${FLUX_ROOT}/cache/cache_valid")" = rust ] ||
        fail "direct cache preview did not publish its Rust cache producer"
}

test_cache_preview_cannot_overlap_generation_attestation() {
    reset_fixture
    install_real_init_fixture
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
case "${1:-}" in
snapshot-legacy-packages)
    cat "${3}"
    ;;
render-legacy-rules)
    printf '*mangle\nCOMMIT\n'
    ;;
attest-legacy-rules-set)
    : >/data/adb/flux/run/attestation-started
    while [ ! -e /data/adb/flux/run/release-attestation ]; do
        sleep 0.01
    done
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n' "${3}"
    ;;
*) exit 2 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"

    run_bridge prepare &
    prepare_pid=$!
    attempts=0
    while [ ! -e "${RUN_ROOT}/attestation-started" ] && [ "${attempts}" -lt 500 ]; do
        sleep 0.01
        attempts=$((attempts + 1))
    done
    [ -e "${RUN_ROOT}/attestation-started" ] || {
        : >"${RUN_ROOT}/release-attestation"
        wait "${prepare_pid}" 2>/dev/null || true
        fail "Generation preparation did not reach attestation"
    }

    preview_rc=0
    run_bridge cache-preview || preview_rc=$?
    [ "${preview_rc}" -eq 75 ] || {
        : >"${RUN_ROOT}/release-attestation"
        wait "${prepare_pid}" 2>/dev/null || true
        fail "cache preview overlapped Generation attestation (rc=${preview_rc})"
    }

    : >"${RUN_ROOT}/release-attestation"
    wait "${prepare_pid}" || fail "serialized Generation preparation failed"
    generation=$(manifest_value generation)
    grep -qx "generation=${generation}" "${GENERATIONS_ROOT}/${generation}/legacy-rules.manifest" ||
        fail "serialized Generation did not retain its attested receipt"
}

test_real_init_keeps_explicit_shell_renderer_rollback_for_legacy_owner() {
    reset_fixture
    install_real_init_fixture
    rm -f "${FLUX_ROOT}/bin/fluxd"
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
generate() {
    printf 'shell-render:%s\n' "$*" >>/data/adb/flux/run/test-calls
    printf '*mangle\nCOMMIT\n'
}
EOF

    run_bridge start || fail "explicit legacy start did not retain the shell renderer"

    grep -qx 'shell-render:-A 4' "${CALLS_FILE}" || fail "legacy apply did not use scripts/rules"
    grep -qx 'shell-render:-D 4' "${CALLS_FILE}" || fail "legacy cleanup did not use scripts/rules"
    [ "$(cat "${FLUX_ROOT}/cache/cache_valid")" = shell ] ||
        fail "legacy cache did not record its shell producer"
    [ ! -e "${FLUX_ROOT}/cache/cache_packages" ] ||
        fail "legacy renderer retained a misleading Rust package snapshot"
}

test_legacy_restart_prepares_before_stopping_the_active_runtime() {
    reset_fixture
    install_real_init_fixture
    rm -f "${FLUX_ROOT}/bin/fluxd"
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
generate() {
    [ ! -e /data/adb/flux/run/fail-shell-render ] || exit 74
    printf '*mangle\nCOMMIT\n'
}
EOF

    run_bridge start || fail "legacy start before restart preflight test failed"
    cp "${RUN_ROOT}/dispatcher.mode" "${RUN_ROOT}/legacy-mode-before-render-failure"
    cp /data/adb/modules/flux/module.prop "${RUN_ROOT}/legacy-prop-before-render-failure"
    : >"${CALLS_FILE}"
    : >"${RUN_ROOT}/fail-shell-render"

    if run_bridge restart; then
        fail "legacy restart accepted a failed replacement render"
    fi

    ! grep -Eq '^(core|tproxy|addrsync):stop$' "${CALLS_FILE}" ||
        fail "legacy restart stopped the active runtime before replacement preparation"
    assert_file_equals "${RUN_ROOT}/legacy-mode-before-render-failure" "${RUN_ROOT}/dispatcher.mode"
    assert_file_equals "${RUN_ROOT}/legacy-prop-before-render-failure" /data/adb/modules/flux/module.prop
    grep -q '\[RUNNING\]' /data/adb/modules/flux/module.prop ||
        fail "failed legacy replacement preparation changed RUNNING state"
    [ "$(cat "${FLUX_ROOT}/cache/cache_valid")" = shell ] ||
        fail "failed legacy replacement preparation did not restore cache authority"

    rm -f "${RUN_ROOT}/fail-shell-render"
    run_bridge stop || fail "legacy stop failed after replacement preparation was rejected"
    grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "legacy stop did not remain available after replacement preparation failure"
}

test_failed_rust_render_preserves_the_active_generation() {
    reset_fixture
    install_real_init_fixture
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
if [ "${1:-}" = snapshot-legacy-packages ]; then
    cat "${3}"
    exit 0
fi
if [ "${1:-}" = attest-legacy-rules-set ]; then
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n' "${3}"
    exit 0
fi
printf '*mangle\nCOMMIT\n'
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"

    active_generation=$(prepare_generation)
    run_bridge capture-start "${active_generation}" || fail "initial capture-start failed"
    run_bridge capture-verify "${active_generation}" || fail "initial capture-verify failed"
    run_bridge state-running "${active_generation}" || fail "initial state-running failed"
    cp "${RUN_ROOT}/capture.active" "${RUN_ROOT}/active-before-render-failure"
    cp "${RUN_ROOT}/capture.verified" "${RUN_ROOT}/verified-before-render-failure"
    cp "${RUN_ROOT}/engine.active" "${RUN_ROOT}/engine-before-render-failure"

    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
if [ "${1:-}" = snapshot-legacy-packages ]; then
    cat "${3}"
    exit 0
fi
if [ "${1:-}" = attest-legacy-rules-set ]; then
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n' "${3}"
    exit 0
fi
case "$*" in
*'--family 4 --action cleanup'*) exit 73 ;;
esac
printf '*mangle\nCOMMIT\n'
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"

    if run_bridge prepare; then
        fail "prepare accepted a partial Rust render"
    fi

    [ ! -e "${RUN_ROOT}/engine.manifest" ] || fail "failed render published a candidate manifest"
    [ ! -d "${GENERATIONS_ROOT}/2" ] || fail "failed render retained a candidate generation"
    [ ! -e "${FLUX_ROOT}/cache/cache_valid" ] || fail "failed render published cache validity"
    assert_file_equals "${RUN_ROOT}/active-before-render-failure" "${RUN_ROOT}/capture.active"
    assert_file_equals "${RUN_ROOT}/verified-before-render-failure" "${RUN_ROOT}/capture.verified"
    assert_file_equals "${RUN_ROOT}/engine-before-render-failure" "${RUN_ROOT}/engine.active"
}

test_failed_rust_attestation_preserves_the_active_generation() {
    reset_fixture
    install_real_init_fixture
    cat >"${FLUX_ROOT}/scripts/rules" <<'EOF'
return 99
EOF
    cat >"${FLUX_ROOT}/bin/fluxd" <<'EOF'
#!/usr/bin/sh
set -eu
case "${1:-}" in
snapshot-legacy-packages)
    cat "${3}"
    ;;
render-legacy-rules)
    case "$*" in
    *'--family 4 --action cleanup'*)
        if [ -f /data/adb/flux/run/tamper-next-rule-set ]; then
            printf '*mangle\n:TAMPERED - [0:0]\nCOMMIT\n'
            exit 0
        fi
        ;;
    esac
    printf '*mangle\nCOMMIT\n'
    ;;
attest-legacy-rules-set)
    if grep -q TAMPERED /data/adb/flux/cache/cache_cleanup_ipv4; then
        printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=999\nfamilies=ipv4\n'
        exit 0
    fi
    printf 'FLUX_LEGACY_RULES_SET_MANIFEST_V1\ngeneration=%s\nfamilies=ipv4\n' "${3}"
    ;;
*) exit 2 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/fluxd"

    active_generation=$(prepare_generation)
    run_bridge capture-start "${active_generation}" || fail "initial capture-start failed"
    run_bridge capture-verify "${active_generation}" || fail "initial capture-verify failed"
    run_bridge state-running "${active_generation}" || fail "initial state-running failed"
    cp "${RUN_ROOT}/capture.active" "${RUN_ROOT}/active-before-attestation-failure"
    cp "${RUN_ROOT}/capture.verified" "${RUN_ROOT}/verified-before-attestation-failure"
    cp "${RUN_ROOT}/engine.active" "${RUN_ROOT}/engine-before-attestation-failure"
    : >"${RUN_ROOT}/tamper-next-rule-set"

    if run_bridge prepare; then
        fail "prepare accepted an attestation receipt for the wrong Generation"
    fi

    [ ! -e "${RUN_ROOT}/engine.manifest" ] || fail "failed attestation published a candidate manifest"
    [ ! -d "${GENERATIONS_ROOT}/2" ] || fail "failed attestation retained a candidate generation"
    [ ! -e "${FLUX_ROOT}/cache/cache_rules_manifest" ] || fail "failed attestation retained a stale shared receipt"
    [ ! -e "${FLUX_ROOT}/cache/cache_valid" ] || fail "failed attestation published cache validity"
    assert_file_equals "${RUN_ROOT}/active-before-attestation-failure" "${RUN_ROOT}/capture.active"
    assert_file_equals "${RUN_ROOT}/verified-before-attestation-failure" "${RUN_ROOT}/capture.verified"
    assert_file_equals "${RUN_ROOT}/engine-before-attestation-failure" "${RUN_ROOT}/engine.active"
}

test_prepare_removes_stale_manifest_on_failure() {
    reset_fixture
    first_generation=$(prepare_generation)
    run_bridge capture-start "${first_generation}" || fail "initial capture-start failed"
    run_bridge capture-verify "${first_generation}" || fail "initial capture-verify failed"
    run_bridge state-running "${first_generation}" || fail "initial state-running failed"
    cp "${GENERATIONS_ROOT}/${first_generation}/config.json" "${RUN_ROOT}/first-config"
    cp "${RUN_ROOT}/capture.active" "${RUN_ROOT}/first-capture-active"
    cp "${RUN_ROOT}/capture.verified" "${RUN_ROOT}/first-capture-verified"
    cp "${RUN_ROOT}/engine.active" "${RUN_ROOT}/first-engine-active"
    printf 'stale\n' >"${RUN_ROOT}/engine.manifest"
    : >"${RUN_ROOT}/fail-init"

    if run_bridge prepare; then
        fail "prepare unexpectedly succeeded"
    fi

    [ ! -e "${RUN_ROOT}/engine.manifest" ] || fail "failed prepare retained stale manifest"
    [ ! -d "${GENERATIONS_ROOT}/2" ] || fail "failed prepare retained incomplete generation"
    assert_file_equals "${RUN_ROOT}/first-config" "${GENERATIONS_ROOT}/${first_generation}/config.json"
    assert_file_equals "${RUN_ROOT}/first-capture-active" "${RUN_ROOT}/capture.active"
    assert_file_equals "${RUN_ROOT}/first-capture-verified" "${RUN_ROOT}/capture.verified"
    assert_file_equals "${RUN_ROOT}/first-engine-active" "${RUN_ROOT}/engine.active"

    rm -f "${RUN_ROOT}/fail-init"
    recovered_generation=$(prepare_generation)
    [ "${recovered_generation}" = "3" ] ||
        fail "failed prepare generation ID was reused"
    assert_not_called core
}

test_prepare_creates_distinct_immutable_generation_artifacts() {
    reset_fixture

    first_generation=$(prepare_generation)
    cp "${GENERATIONS_ROOT}/${first_generation}/config.json" "${RUN_ROOT}/first-config"
    cp "${GENERATIONS_ROOT}/${first_generation}/cache_config" "${RUN_ROOT}/first-env"
    cp "${GENERATIONS_ROOT}/${first_generation}/cache_rules_ipv4" "${RUN_ROOT}/first-rules"

    printf '{"revision":2}\n' >"${FLUX_ROOT}/conf/config.json"
    sed -i 's/^PROXY_PORT=.*/PROXY_PORT=2536/' "${FLUX_ROOT}/cache/cache_config"
    printf '*mangle\n:GENERATION_TWO - [0:0]\nCOMMIT\n' >"${FLUX_ROOT}/cache/cache_rules_ipv4"
    second_generation=$(prepare_generation)

    [ "${first_generation}" = "1" ] || fail "first prepare returned ${first_generation}"
    [ "${second_generation}" = "2" ] || fail "second prepare returned ${second_generation}"
    assert_file_equals "${RUN_ROOT}/first-config" "${GENERATIONS_ROOT}/${first_generation}/config.json"
    assert_file_equals "${RUN_ROOT}/first-env" "${GENERATIONS_ROOT}/${first_generation}/cache_config"
    assert_file_equals "${RUN_ROOT}/first-rules" "${GENERATIONS_ROOT}/${first_generation}/cache_rules_ipv4"
    grep -qx 'PROXY_PORT=2536' "${GENERATIONS_ROOT}/${second_generation}/cache_config" ||
        fail "second generation did not snapshot its environment"
    grep -q 'GENERATION_TWO' "${GENERATIONS_ROOT}/${second_generation}/cache_rules_ipv4" ||
        fail "second generation did not snapshot its rules"
    grep -qx "generation=${second_generation}" "${GENERATIONS_ROOT}/${second_generation}/legacy-rules.manifest" ||
        fail "second generation reused a receipt bound to the first Generation"
    [ "$(manifest_value config)" = "${GENERATIONS_ROOT}/${second_generation}/config.json" ] ||
        fail "top-level manifest does not select the latest generation"
    assert_not_called core
}

test_previous_generation_can_be_selected_after_newer_prepare() {
    reset_fixture

    first_generation=$(prepare_generation)
    run_bridge capture-start "${first_generation}" || fail "initial capture-start failed"
    run_bridge capture-verify "${first_generation}" || fail "initial capture-verify failed"
    run_bridge state-running "${first_generation}" || fail "initial state-running failed"

    printf '{"revision":2}\n' >"${FLUX_ROOT}/conf/config.json"
    sed -i 's/^PROXY_PORT=.*/PROXY_PORT=2536/' "${FLUX_ROOT}/cache/cache_config"
    second_generation=$(prepare_generation)
    [ "${second_generation}" = "2" ] || fail "newer prepare did not allocate generation 2"

    run_bridge capture-stop || fail "detach before rollback failed"
    : >"${ENV_CALLS_FILE}"
    run_bridge capture-start "${first_generation}" || fail "old generation capture-start failed"
    run_bridge capture-verify "${first_generation}" || fail "old generation capture-verify failed"
    run_bridge state-running "${first_generation}" || fail "old generation publication failed"

    grep -q "^tproxy:start:generation=${first_generation}:port=1536:cache=${GENERATIONS_ROOT}/${first_generation}/cache_rules_ipv4$" "${ENV_CALLS_FILE}" ||
        fail "rollback used the newer shared cache instead of the old generation"
    grep -qx "${first_generation} $(cat /proc/sys/kernel/random/boot_id)" "${RUN_ROOT}/engine.active" ||
        fail "rollback did not republish the old generation"
    [ -d "${GENERATIONS_ROOT}/${first_generation}" ] || fail "rollback generation was pruned"
    assert_not_called core
}

test_generation_mismatch_is_rejected_for_verification_and_publication() {
    reset_fixture

    first_generation=$(prepare_generation)
    sed -i 's/^PROXY_PORT=.*/PROXY_PORT=2536/' "${FLUX_ROOT}/cache/cache_config"
    second_generation=$(prepare_generation)
    run_bridge capture-start "${first_generation}" || fail "capture-start for generation mismatch test failed"

    if run_bridge capture-verify "${second_generation}"; then
        fail "capture-verify accepted a generation other than the attached capture"
    fi
    [ ! -e "${RUN_ROOT}/capture.verified" ] || fail "mismatched verification published evidence"

    run_bridge capture-verify "${first_generation}" || fail "matching capture-verify failed"
    if run_bridge state-running "${second_generation}"; then
        fail "state-running accepted a generation other than the verified capture"
    fi
    [ ! -e "${RUN_ROOT}/engine.active" ] || fail "mismatched publication changed active generation"

    run_bridge state-running "${first_generation}" || fail "matching state-running failed"
    assert_not_called core
}

test_running_publication_retains_only_current_and_previous_generations() {
    reset_fixture

    first_generation=$(prepare_generation)
    run_bridge capture-start "${first_generation}" || fail "generation 1 capture-start failed"
    run_bridge capture-verify "${first_generation}" || fail "generation 1 capture-verify failed"
    run_bridge state-running "${first_generation}" || fail "generation 1 state-running failed"

    sed -i 's/^PROXY_PORT=.*/PROXY_PORT=2536/' "${FLUX_ROOT}/cache/cache_config"
    second_generation=$(prepare_generation)
    run_bridge capture-stop || fail "generation 1 detach failed"
    run_bridge capture-start "${second_generation}" || fail "generation 2 capture-start failed"
    run_bridge capture-verify "${second_generation}" || fail "generation 2 capture-verify failed"
    run_bridge state-running "${second_generation}" || fail "generation 2 state-running failed"

    sed -i 's/^PROXY_PORT=.*/PROXY_PORT=3536/' "${FLUX_ROOT}/cache/cache_config"
    third_generation=$(prepare_generation)
    run_bridge capture-stop || fail "generation 2 detach failed"
    run_bridge capture-start "${third_generation}" || fail "generation 3 capture-start failed"
    run_bridge capture-verify "${third_generation}" || fail "generation 3 capture-verify failed"
    run_bridge state-running "${third_generation}" || fail "generation 3 state-running failed"

    [ ! -e "${GENERATIONS_ROOT}/${first_generation}" ] || fail "retired generation 1 was not pruned"
    [ -d "${GENERATIONS_ROOT}/${second_generation}" ] || fail "previous generation 2 was pruned"
    [ -d "${GENERATIONS_ROOT}/${third_generation}" ] || fail "current generation 3 was pruned"
    assert_not_called core
}

test_prepare_writes_exact_busybox_manifest() {
    reset_fixture
    sed -i 's/^CORE_USER=.*/CORE_USER=1000/' "${FLUX_ROOT}/cache/cache_config"
    sed -i 's/^CORE_GROUP=.*/CORE_GROUP=3003/' "${FLUX_ROOT}/cache/cache_config"
    printf '#!/usr/bin/sh\nexit 0\n' >/data/adb/magisk/busybox
    chmod 0755 /data/adb/magisk/busybox

    generation=$(prepare_generation)
    [ "${generation}" = "1" ] || fail "BusyBox generation must be 1"

    cat >"${RUN_ROOT}/expected-manifest" <<'EOF'
FLUX_ENGINE_MANIFEST_V1
generation=1
binary=/data/adb/flux/bin/sing-box
config=/data/adb/flux/run/generations/1/config.json
working_directory=/data/adb/flux/run
log=/data/adb/flux/run/generations/1/sing-box.log
launcher=busybox-setuidgid
busybox=/data/adb/magisk/busybox
identity=1000:3003
readiness=listener
startup_timeout_ms=5000
stop_timeout_ms=5000
listener_port=1536
EOF
    assert_file_equals "${RUN_ROOT}/expected-manifest" "${RUN_ROOT}/engine.manifest"
    assert_not_called core
}

test_prepare_rejects_tun_before_init_or_manifest() {
    reset_fixture
    sed -i 's/^PROXY_MODE=.*/PROXY_MODE=tun/' "${FLUX_ROOT}/cache/cache_config"
    sed -i 's/^TUN_INTERFACE=.*/TUN_INTERFACE=flux-tun0/' "${FLUX_ROOT}/cache/cache_config"
    : >"${CALLS_FILE}"

    if run_bridge prepare; then
        fail "Rust-owned prepare admitted unsupported TUN mode"
    fi

    assert_not_called init
    assert_not_called core
    [ ! -e "${RUN_ROOT}/engine.manifest" ] ||
        fail "rejected TUN prepare published an engine manifest"
    [ ! -d "${GENERATIONS_ROOT}/1" ] ||
        fail "rejected TUN prepare retained incomplete generation artifacts"
}

test_prepare_rejects_missing_proxy_mode_without_artifacts() {
    reset_fixture
    sed -i '/^PROXY_MODE=/d' "${FLUX_ROOT}/cache/cache_config"
    : >"${CALLS_FILE}"

    if run_bridge prepare; then
        fail "Rust-owned prepare admitted a missing proxy mode"
    fi

    assert_not_called init
    [ ! -e "${RUN_ROOT}/engine.manifest" ] ||
        fail "missing-mode prepare published an engine manifest"
    [ ! -d "${GENERATIONS_ROOT}/1" ] ||
        fail "missing-mode prepare retained incomplete generation artifacts"
}

test_prepare_revalidates_proxy_mode_generated_by_init() {
    reset_fixture
    write_stub init '
printf "init:%s\n" "$*" >>/data/adb/flux/run/test-calls
sed -i "s/^PROXY_MODE=.*/PROXY_MODE=tun/" /data/adb/flux/cache/cache_config
: >/data/adb/flux/cache/cache_valid
exit 0'

    if run_bridge prepare; then
        fail "Rust-owned prepare trusted the pre-init mode after init generated TUN"
    fi

    grep -qx 'init:init' "${CALLS_FILE}" ||
        fail "generated-mode test did not exercise init"
    [ ! -e "${RUN_ROOT}/engine.manifest" ] ||
        fail "init-generated TUN published an engine manifest"
    [ ! -d "${GENERATIONS_ROOT}/1" ] ||
        fail "init-generated TUN retained incomplete generation artifacts"
}

test_active_tproxy_prepare_rejects_tun_without_disturbance() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "initial capture-start failed"
    run_bridge capture-verify "${generation}" || fail "initial capture-verify failed"
    run_bridge state-running "${generation}" || fail "initial state-running failed"
    cp "${RUN_ROOT}/capture.active" "${RUN_ROOT}/tproxy-capture-active"
    cp "${RUN_ROOT}/capture.verified" "${RUN_ROOT}/tproxy-capture-verified"
    cp "${RUN_ROOT}/engine.active" "${RUN_ROOT}/tproxy-engine-active"
    sed -i 's/^PROXY_MODE=.*/PROXY_MODE=tun/' "${FLUX_ROOT}/cache/cache_config"

    if run_bridge prepare; then
        fail "active TPROXY generation admitted a TUN replacement"
    fi

    [ ! -e "${RUN_ROOT}/engine.manifest" ] ||
        fail "rejected TUN replacement retained a candidate manifest"
    [ ! -d "${GENERATIONS_ROOT}/2" ] ||
        fail "rejected TUN replacement retained candidate artifacts"
    assert_file_equals "${RUN_ROOT}/tproxy-capture-active" "${RUN_ROOT}/capture.active"
    assert_file_equals "${RUN_ROOT}/tproxy-capture-verified" "${RUN_ROOT}/capture.verified"
    assert_file_equals "${RUN_ROOT}/tproxy-engine-active" "${RUN_ROOT}/engine.active"
}

test_rust_owned_config_build_skips_unpinned_sing_box_check() {
    reset_fixture
    cat >"${FLUX_ROOT}/bin/sing-box" <<'EOF'
#!/usr/bin/sh
printf 'sing-box:%s\n' "$*" >>/data/adb/flux/run/test-calls
exit 99
EOF
    chmod 0755 "${FLUX_ROOT}/bin/sing-box"
    : >"${CALLS_FILE}"

    FLUXD_ENGINE_OWNER=rust sh -c '
        . /data/adb/flux/scripts/lib
        . /data/adb/flux/scripts/log
        . /src/scripts/config
        _extract_json_config() { :; }
        _process_settings() { printf "%s\n" "CORE_TIMEOUT=5"; }
        _apply_proxy_mode_config() { :; }
        _detect_kernel() { :; }
        build_config >/dev/null
    ' || fail "Rust-owned config build invoked shell validation"

    assert_not_called sing-box
}

test_prepare_rejects_missing_xt_owner_before_init_or_generation_publication() {
    reset_fixture
    sed -i 's/^KFEAT_OWNER=.*/KFEAT_OWNER=0/' "${FLUX_ROOT}/cache/cache_config"
    : >"${CALLS_FILE}"

    if run_bridge prepare; then
        fail "prepare accepted Rust-owned capture without xt_owner loop prevention"
    fi

    assert_not_called init
    [ ! -e "${RUN_ROOT}/engine.manifest" ] ||
        fail "xt_owner rejection published an engine manifest"
    [ ! -d "${GENERATIONS_ROOT}/1" ] ||
        fail "xt_owner rejection retained incomplete generation artifacts"
    [ ! -e "${RUN_ROOT}/capture.active" ] ||
        fail "xt_owner rejection published capture ownership"
    assert_not_called core
    assert_not_called addrsync
    assert_not_called tproxy
}

test_prepare_revalidates_xt_owner_generated_by_init() {
    reset_fixture
    write_stub init '
printf "init:%s\n" "$*" >>/data/adb/flux/run/test-calls
sed -i "s/^KFEAT_OWNER=.*/KFEAT_OWNER=0/" /data/adb/flux/cache/cache_config
: >/data/adb/flux/cache/cache_valid
exit 0'

    if run_bridge prepare; then
        fail "Rust-owned prepare trusted pre-init xt_owner after generated capability mismatch"
    fi

    grep -qx 'init:init' "${CALLS_FILE}" ||
        fail "generated xt_owner test did not exercise init"
    [ ! -e "${RUN_ROOT}/engine.manifest" ] ||
        fail "init-generated missing xt_owner published an engine manifest"
    [ ! -d "${GENERATIONS_ROOT}/1" ] ||
        fail "init-generated missing xt_owner retained incomplete generation artifacts"
    [ ! -e "${RUN_ROOT}/capture.active" ] ||
        fail "init-generated missing xt_owner published capture ownership"
    assert_not_called core
    assert_not_called addrsync
    assert_not_called tproxy
}

test_capture_start_owns_only_addrsync_and_tproxy() {
    reset_fixture
    generation=$(prepare_generation)
    : >"${CALLS_FILE}"
    : >"${ENV_CALLS_FILE}"

    run_bridge capture-start "${generation}" || fail "capture-start failed"

    cat >"${RUN_ROOT}/expected-calls" <<'EOF'
addrsync:start
tproxy:start
EOF
    assert_file_equals "${RUN_ROOT}/expected-calls" "${CALLS_FILE}"
    [ -s "${RUN_ROOT}/capture.active" ] || fail "capture-start did not publish active marker"
    grep -q "^tproxy:start:generation=${generation}:port=1536:cache=${GENERATIONS_ROOT}/${generation}/cache_rules_ipv4$" "${ENV_CALLS_FILE}" ||
        fail "capture-start did not bind TProxy to the requested generation"
    assert_not_called core
}

test_capture_start_compensates_partial_failure() {
    reset_fixture
    generation=$(prepare_generation)
    : >"${CALLS_FILE}"
    : >"${RUN_ROOT}/fail-tproxy-start"

    if run_bridge capture-start "${generation}"; then
        fail "capture-start unexpectedly survived TPROXY failure"
    fi

    cat >"${RUN_ROOT}/expected-calls" <<'EOF'
addrsync:start
tproxy:start
tproxy:stop
addrsync:stop
EOF
    assert_file_equals "${RUN_ROOT}/expected-calls" "${CALLS_FILE}"
    [ ! -e "${RUN_ROOT}/capture.active" ] || fail "failed capture-start published active"
    [ ! -e "${RUN_ROOT}/capture.verified" ] || fail "failed capture-start published verified"
    assert_not_called core
}

test_capture_start_preserves_retry_evidence_when_compensation_fails() {
    reset_fixture
    generation=$(prepare_generation)
    write_stub tproxy '
. /data/adb/flux/scripts/lib
printf "tproxy:%s\n" "$*" >>/data/adb/flux/run/test-calls
case "${1:-}" in
    start) exit 42 ;;
    stop)
        [ ! -f /data/adb/flux/run/fail-tproxy-stop ] || exit 43
        rm -f /data/adb/flux/run/active_runtime /data/adb/flux/run/active_cleanup_ipv4
        ;;
esac
exit 0'
    : >"${RUN_ROOT}/fail-tproxy-stop"
    : >"${CALLS_FILE}"

    if run_bridge capture-start "${generation}"; then
        fail "capture-start unexpectedly survived failed compensation"
    fi

    [ -s "${RUN_ROOT}/capture.active" ] ||
        fail "failed compensation discarded the generation retry marker"
    rm -f "${RUN_ROOT}/fail-tproxy-stop"
    run_bridge capture-stop || fail "capture-stop did not retry failed compensation"
    [ ! -e "${RUN_ROOT}/capture.active" ] ||
        fail "successful compensation retry retained the generation marker"
    cat >"${RUN_ROOT}/expected-calls" <<'EOF'
addrsync:start
tproxy:start
tproxy:stop
addrsync:stop
tproxy:stop
addrsync:stop
EOF
    assert_file_equals "${RUN_ROOT}/expected-calls" "${CALLS_FILE}"
}

test_capture_stop_is_ordered_and_idempotent() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before stop failed"
    : >"${CALLS_FILE}"
    : >"${ENV_CALLS_FILE}"

    run_bridge capture-stop || fail "first capture-stop failed"
    run_bridge capture-stop || fail "second capture-stop failed"

    cat >"${RUN_ROOT}/expected-calls" <<'EOF'
tproxy:stop
addrsync:stop
EOF
    assert_file_equals "${RUN_ROOT}/expected-calls" "${CALLS_FILE}"
    grep -q "^tproxy:stop:generation=${generation}:port=1536:cache=${GENERATIONS_ROOT}/${generation}/cache_rules_ipv4$" "${ENV_CALLS_FILE}" ||
        fail "capture-stop did not load the attached generation"
    [ ! -e "${RUN_ROOT}/capture.active" ] || fail "capture-stop retained active marker"
    [ ! -e "${RUN_ROOT}/capture.verified" ] || fail "capture-stop retained verified marker"
    assert_not_called core
}

test_native_xtables_lease_blocks_dispatcher_shell_writers() {
    reset_fixture
    generation=$(prepare_generation)
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"
    : >"${CALLS_FILE}"

    if run_bridge capture-start "${generation}"; then
        fail "capture-start ran while the native xtables lease existed"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    [ ! -e "${RUN_ROOT}/capture.active" ] ||
        fail "rejected shell capture-start published capture ownership"
}

test_native_xtables_lease_blocks_legacy_start_before_network_mutation() {
    reset_fixture
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"
    : >"${CALLS_FILE}"

    if run_bridge start; then
        fail "legacy start ran while the native xtables lease existed"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    assert_not_called core
}

test_native_xtables_lease_blocks_ambient_internal_writer_state() {
    reset_fixture
    owner_start=$(process_start_ticks_for_test "$$")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"
    : >"${CALLS_FILE}"

    if XTABLES_WRITER_LOCK_OWNED=1 \
        XTABLES_WRITER_OWNER_PID="$$" \
        XTABLES_WRITER_OWNER_START_TICKS="${owner_start}" \
        XTABLES_WRITER_OWNER_BOOT_ID="${owner_boot}" \
        XTABLES_WRITER_PARENT_PID="$$" \
        XTABLES_WRITER_PARENT_START_TICKS="${owner_start}" \
        XTABLES_WRITER_PARENT_BOOT_ID="${owner_boot}" \
        XTABLES_WRITER_CHILD_PID=2147483647 \
        XTABLES_WRITER_CHILD_START_TICKS=1 \
        FLUXD_BRIDGE=1 sh "${DISPATCHER}" start; then
        fail "ambient internal writer state bypassed the native lease"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    assert_not_called core
}

test_native_xtables_lease_blocks_legacy_stop_before_network_mutation() {
    reset_fixture
    run_bridge start || fail "legacy start before lease-blocked stop failed"
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"
    : >"${CALLS_FILE}"

    if run_bridge stop; then
        fail "legacy stop ran while the native xtables lease existed"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    assert_not_called core
}

test_native_xtables_lease_blocks_legacy_restart_before_network_mutation() {
    reset_fixture
    run_bridge start || fail "legacy start before lease-blocked restart failed"
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"
    : >"${CALLS_FILE}"

    if run_bridge restart; then
        fail "legacy restart ran while the native xtables lease existed"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    assert_not_called core
}

test_native_xtables_lease_blocks_legacy_failure_cleanup_mutation() {
    reset_fixture
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"
    : >"${RUN_ROOT}/fail-init"
    : >"${CALLS_FILE}"

    if run_bridge start; then
        fail "legacy start unexpectedly survived its failed initialization"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    assert_not_called core
}

test_native_xtables_lease_blocks_direct_tproxy_mutation() {
    reset_fixture
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"

    if sh /src/scripts/tproxy start; then
        fail "direct tproxy start ran while the native xtables lease existed"
    fi
    if sh /src/scripts/tproxy stop; then
        fail "direct tproxy stop ran while the native xtables lease existed"
    fi

    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "rejected direct tproxy retained the transition lock"
}

test_native_xtables_lease_blocks_direct_addrsync_mutation_but_not_status() {
    reset_fixture
    cat >"${FLUX_ROOT}/bin/addrsyncd" <<'EOF'
#!/usr/bin/sh
action="${5:-}"
printf '%s\n' "${action}" >>/data/adb/flux/run/addrsyncd-actions
case "${action}" in
status) printf 'running pid=4242\n' ;;
*) exit 0 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/addrsyncd"
    printf 'stale-or-live-native-owner\n' >"${RUN_ROOT}/native_xtables.lease"

    for action in start stop resync cleanup; do
        if sh /src/scripts/addrsync "${action}"; then
            fail "direct addrsync ${action} ran while the native xtables lease existed"
        fi
        [ ! -e "${RUN_ROOT}/addrsyncd-actions" ] ||
            fail "lease-blocked addrsync ${action} invoked addrsyncd"
        [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
            fail "lease-blocked addrsync ${action} retained the transition lock"
    done

    sh /src/scripts/addrsync status >"${RUN_ROOT}/addrsync-status" ||
        fail "read-only addrsync status was blocked by the native lease"
    grep -qx 'running pid=4242' "${RUN_ROOT}/addrsync-status" ||
        fail "read-only addrsync status did not report the daemon result"
    printf 'status\n' >"${RUN_ROOT}/expected-addrsyncd-actions"
    assert_file_equals \
        "${RUN_ROOT}/expected-addrsyncd-actions" \
        "${RUN_ROOT}/addrsyncd-actions"
    [ -f "${RUN_ROOT}/native_xtables.lease" ] ||
        fail "rejected direct addrsync mutation removed the native lease"
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "read-only addrsync status created a writer lock"
}

test_xtables_transition_lock_blocks_shell_writers() {
    reset_fixture
    generation=$(prepare_generation)
    mkdir "${RUN_ROOT}/xtables-writer.lock"
    : >"${CALLS_FILE}"

    if run_bridge capture-start "${generation}"; then
        fail "capture-start ran while the xtables transition lock was held"
    fi
    if sh /src/scripts/tproxy start; then
        fail "direct tproxy ran while the xtables transition lock was held"
    fi

    assert_not_called tproxy
    assert_not_called addrsync
    [ -d "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "rejected shell writers removed a transition lock they did not own"
}

test_spoofed_inherited_xtables_writer_metadata_is_rejected() {
    reset_fixture
    sleep 30 &
    owner_pid=$!
    owner_start=$(process_start_ticks_for_test "${owner_pid}")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        "${owner_pid}" "${owner_start}" 0 0 "${owner_boot}"

    if FLUX_XTABLES_WRITER_OWNER_PID="${owner_pid}" \
        FLUX_XTABLES_WRITER_OWNER_START_TICKS="${owner_start}" \
        FLUX_XTABLES_WRITER_OWNER_BOOT_ID="${owner_boot}" \
        sh /src/scripts/tproxy invalid >"${RUN_ROOT}/spoof-error" 2>&1; then
        kill "${owner_pid}" 2>/dev/null || true
        wait "${owner_pid}" 2>/dev/null || true
        fail "spoofed inherited writer metadata reached tproxy"
    fi
    kill "${owner_pid}" 2>/dev/null || true
    wait "${owner_pid}" 2>/dev/null || true

    grep -q 'Inherited xtables writer ownership is invalid' "${RUN_ROOT}/spoof-error" ||
        fail "spoofed inherited writer metadata was not rejected at the ownership boundary"
    [ -f "${RUN_ROOT}/xtables-writer.lock/shell-owner" ] ||
        fail "spoofed child removed the live owner record"
}

test_valid_parent_bound_xtables_writer_metadata_reaches_tproxy() {
    reset_fixture
    owner_start=$(process_start_ticks_for_test "$$")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner "$$" "${owner_start}" 0 0 "${owner_boot}"

    if FLUX_XTABLES_WRITER_OWNER_PID="$$" \
        FLUX_XTABLES_WRITER_OWNER_START_TICKS="${owner_start}" \
        FLUX_XTABLES_WRITER_OWNER_BOOT_ID="${owner_boot}" \
        sh /src/scripts/tproxy invalid >"${RUN_ROOT}/valid-owner-output" 2>&1; then
        fail "invalid tproxy action unexpectedly succeeded"
    fi

    grep -q '^Usage:' "${RUN_ROOT}/valid-owner-output" ||
        fail "valid parent-bound writer metadata did not reach the tproxy action boundary"
    assert_shell_xtables_writer_parent_only "$$" "${owner_start}" "${owner_boot}"
}

test_dead_stale_child_for_same_live_parent_can_be_replaced() {
    reset_fixture
    owner_start=$(process_start_ticks_for_test "$$")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        "$$" "${owner_start}" 2147483647 1 "${owner_boot}"

    if FLUX_XTABLES_WRITER_OWNER_PID="$$" \
        FLUX_XTABLES_WRITER_OWNER_START_TICKS="${owner_start}" \
        FLUX_XTABLES_WRITER_OWNER_BOOT_ID="${owner_boot}" \
        sh /src/scripts/tproxy invalid >"${RUN_ROOT}/stale-child-output" 2>&1; then
        fail "invalid tproxy action unexpectedly succeeded"
    fi
    grep -q '^Usage:' "${RUN_ROOT}/stale-child-output" ||
        fail "same-parent tproxy did not replace a dead stale child"
    assert_shell_xtables_writer_parent_only "$$" "${owner_start}" "${owner_boot}"
}

test_live_child_record_cannot_be_replaced() {
    reset_fixture
    sleep 30 &
    child_pid=$!
    owner_start=$(process_start_ticks_for_test "$$")
    child_start=$(process_start_ticks_for_test "${child_pid}")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        "$$" "${owner_start}" "${child_pid}" "${child_start}" "${owner_boot}"

    if FLUX_XTABLES_WRITER_OWNER_PID="$$" \
        FLUX_XTABLES_WRITER_OWNER_START_TICKS="${owner_start}" \
        FLUX_XTABLES_WRITER_OWNER_BOOT_ID="${owner_boot}" \
        sh /src/scripts/tproxy invalid >"${RUN_ROOT}/live-child-output" 2>&1; then
        kill "${child_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
        fail "live child writer record was replaced"
    fi
    kill "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true

    grep -q 'Inherited xtables writer ownership is invalid' \
        "${RUN_ROOT}/live-child-output" ||
        fail "live child writer record was not rejected at inheritance"
    grep -qx \
        "flux-shell-xtables-writer-owner-v2 $$ ${owner_start} ${child_pid} ${child_start} ${owner_boot}" \
        "${RUN_ROOT}/xtables-writer.lock/shell-owner" ||
        fail "rejected child replacement changed the live owner record"
}

test_nonparticipant_cannot_forge_parent_release_state() {
    reset_fixture
    sleep 30 &
    owner_pid=$!
    owner_start=$(process_start_ticks_for_test "${owner_pid}")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        "${owner_pid}" "${owner_start}" 0 0 "${owner_boot}"
    cp "${RUN_ROOT}/xtables-writer.lock/shell-owner" \
        "${RUN_ROOT}/forged-parent-release-before"

    if sh -c '
. /src/scripts/lib
XTABLES_WRITER_LOCK_OWNED=1
XTABLES_WRITER_OWNER_PID="$1"
XTABLES_WRITER_OWNER_START_TICKS="$2"
XTABLES_WRITER_OWNER_BOOT_ID="$3"
XTABLES_WRITER_PARENT_PID="$1"
XTABLES_WRITER_PARENT_START_TICKS="$2"
XTABLES_WRITER_PARENT_BOOT_ID="$3"
release_shell_xtables_writer_lock
' sh "${owner_pid}" "${owner_start}" "${owner_boot}"; then
        kill "${owner_pid}" 2>/dev/null || true
        wait "${owner_pid}" 2>/dev/null || true
        fail "nonparticipant forged a parent writer release"
    fi

    assert_file_equals \
        "${RUN_ROOT}/forged-parent-release-before" \
        "${RUN_ROOT}/xtables-writer.lock/shell-owner"
    kill "${owner_pid}" 2>/dev/null || true
    wait "${owner_pid}" 2>/dev/null || true
}

test_nonparticipant_cannot_forge_child_release_state() {
    reset_fixture
    sleep 30 &
    owner_pid=$!
    sleep 30 &
    child_pid=$!
    owner_start=$(process_start_ticks_for_test "${owner_pid}")
    child_start=$(process_start_ticks_for_test "${child_pid}")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        "${owner_pid}" "${owner_start}" \
        "${child_pid}" "${child_start}" "${owner_boot}"
    cp "${RUN_ROOT}/xtables-writer.lock/shell-owner" \
        "${RUN_ROOT}/forged-child-release-before"

    if sh -c '
. /src/scripts/lib
XTABLES_WRITER_LOCK_OWNED=2
XTABLES_WRITER_OWNER_PID="$1"
XTABLES_WRITER_OWNER_START_TICKS="$2"
XTABLES_WRITER_OWNER_BOOT_ID="$5"
XTABLES_WRITER_PARENT_PID="$1"
XTABLES_WRITER_PARENT_START_TICKS="$2"
XTABLES_WRITER_PARENT_BOOT_ID="$5"
XTABLES_WRITER_CHILD_PID="$3"
XTABLES_WRITER_CHILD_START_TICKS="$4"
release_shell_xtables_writer_lock
' sh "${owner_pid}" "${owner_start}" "${child_pid}" "${child_start}" "${owner_boot}"; then
        kill "${owner_pid}" "${child_pid}" 2>/dev/null || true
        wait "${owner_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
        fail "nonparticipant forged a child writer release"
    fi

    assert_file_equals \
        "${RUN_ROOT}/forged-child-release-before" \
        "${RUN_ROOT}/xtables-writer.lock/shell-owner"
    kill "${owner_pid}" "${child_pid}" 2>/dev/null || true
    wait "${owner_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
}

test_sigkilled_child_keeps_live_parent_busy_until_parent_release() {
    reset_fixture
    start_shell_xtables_writer_pair

    kill -9 "${WRITER_CHILD_PID}" 2>/dev/null || true
    wait_for_test_file "${RUN_ROOT}/writer-child-finished" "parent child reap"
    assert_direct_tproxy_writer_blocked \
        "${RUN_ROOT}/killed-child-competitor" "live parent after child SIGKILL"

    : >"${RUN_ROOT}/writer-parent-release"
    wait "${WRITER_PARENT_PID}" || fail "live parent could not reclaim its dead child"
    wait_for_test_file "${RUN_ROOT}/writer-parent-released" "parent writer release"
    assert_direct_tproxy_writer_recovered \
        "${RUN_ROOT}/parent-release-competitor" "the parent-released writer lock"
}

test_sigkilled_parent_keeps_live_child_busy_until_child_release() {
    reset_fixture
    start_shell_xtables_writer_pair

    kill -9 "${WRITER_PARENT_PID}" 2>/dev/null || true
    wait "${WRITER_PARENT_PID}" 2>/dev/null || true
    assert_direct_tproxy_writer_blocked \
        "${RUN_ROOT}/killed-parent-competitor" "live child after parent SIGKILL"

    : >"${RUN_ROOT}/writer-child-release"
    wait_for_test_file "${RUN_ROOT}/writer-child-released" "orphaned child release"
    assert_direct_tproxy_writer_recovered \
        "${RUN_ROOT}/child-release-competitor" "the orphaned child-released writer lock"
}

test_sigkilled_dispatcher_keeps_live_addrsync_phase_fenced() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" ||
        fail "capture-start before addrsync phase crash test failed"
    run_bridge capture-verify "${generation}" ||
        fail "capture-verify before addrsync phase crash test failed"
    run_bridge state-running "${generation}" ||
        fail "state-running before addrsync phase crash test failed"
    write_stub addrsync '
. /data/adb/flux/scripts/lib
inherited=0
if [ -n "${FLUX_XTABLES_WRITER_OWNER_PID:-}" ] ||
    [ -n "${FLUX_XTABLES_WRITER_OWNER_START_TICKS:-}" ] ||
    [ -n "${FLUX_XTABLES_WRITER_OWNER_BOOT_ID:-}" ]; then
    inherit_shell_xtables_writer_lock || exit 90
    inherited=1
    trap '\''release_shell_xtables_writer_lock'\'' EXIT
    trap '\''exit 130'\'' INT
    trap '\''exit 143'\'' TERM
fi
printf "%s\n" "$$" >/data/adb/flux/run/addrsync-phase-pid
: >/data/adb/flux/run/addrsync-phase-ready
while [ ! -e /data/adb/flux/run/addrsync-phase-release ]; do
    sleep 0.01
done
if [ "${inherited}" -eq 1 ]; then
    release_shell_xtables_writer_lock || exit 91
    trap - EXIT INT TERM
fi
: >/data/adb/flux/run/addrsync-phase-released
exit 0'

    FLUXD_BRIDGE=1 sh "${DISPATCHER}" address-resync &
    dispatcher_pid=$!
    wait_for_test_file "${RUN_ROOT}/addrsync-phase-ready" "live addrsync phase child"
    kill -9 "${dispatcher_pid}" 2>/dev/null || true
    wait "${dispatcher_pid}" 2>/dev/null || true

    assert_direct_tproxy_writer_blocked \
        "${RUN_ROOT}/live-addrsync-phase-competitor" \
        "live addrsync phase after dispatcher SIGKILL"

    : >"${RUN_ROOT}/addrsync-phase-release"
    wait_for_test_file "${RUN_ROOT}/addrsync-phase-released" "addrsync phase release"
    assert_direct_tproxy_writer_recovered \
        "${RUN_ROOT}/released-addrsync-phase-competitor" \
        "the released addrsync phase writer lock"
}

test_both_dead_shell_xtables_writer_participants_are_recovered() {
    reset_fixture
    start_shell_xtables_writer_pair

    kill -9 "${WRITER_PARENT_PID}" 2>/dev/null || true
    kill -9 "${WRITER_CHILD_PID}" 2>/dev/null || true
    wait "${WRITER_PARENT_PID}" 2>/dev/null || true
    wait_for_test_pid_dead "${WRITER_CHILD_PID}" "killed writer child"
    assert_direct_tproxy_writer_recovered \
        "${RUN_ROOT}/both-dead-competitor" "both dead writer participants"
}

test_dead_shell_xtables_writer_lock_is_recovered_before_direct_claim() {
    reset_fixture
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        2147483646 1 2147483647 1 "${owner_boot}"

    if sh /src/scripts/tproxy invalid >"${RUN_ROOT}/dead-owner-error" 2>&1; then
        fail "invalid tproxy action unexpectedly succeeded"
    fi

    grep -q '^Usage:' "${RUN_ROOT}/dead-owner-error" ||
        fail "direct tproxy did not progress past stale-lock recovery"
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "direct tproxy retained a dead shell writer lock"
}

test_pid_reused_shell_xtables_writer_participants_are_recovered() {
    reset_fixture
    sleep 30 &
    child_pid=$!
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner "$$" 1 "${child_pid}" 1 "${owner_boot}"

    assert_direct_tproxy_writer_recovered \
        "${RUN_ROOT}/pid-reused-error" "PID-reused writer participants"
    kill "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
}

test_previous_boot_shell_xtables_writer_lock_is_recovered() {
    reset_fixture
    sleep 30 &
    child_pid=$!
    write_shell_xtables_writer_owner \
        "$$" "$(process_start_ticks_for_test "$$")" \
        "${child_pid}" "$(process_start_ticks_for_test "${child_pid}")" \
        aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa

    if sh /src/scripts/tproxy invalid >"${RUN_ROOT}/previous-boot-error" 2>&1; then
        fail "invalid tproxy action unexpectedly succeeded"
    fi

    grep -q '^Usage:' "${RUN_ROOT}/previous-boot-error" ||
        fail "direct tproxy did not recover the previous-boot shell lock"
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "previous-boot shell writer lock was not retired"
    kill "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
}

test_malformed_shell_xtables_writer_record_fails_closed() {
    reset_fixture
    mkdir "${RUN_ROOT}/xtables-writer.lock"
    printf '%s\n' '123 456 invalid-v1-record' \
        >"${RUN_ROOT}/xtables-writer.lock/shell-owner"

    assert_direct_tproxy_writer_blocked \
        "${RUN_ROOT}/malformed-owner-error" "malformed shell writer record"
    grep -qx '123 456 invalid-v1-record' \
        "${RUN_ROOT}/xtables-writer.lock/shell-owner" ||
        fail "failed-closed malformed record was modified"
}

test_unverifiable_live_participant_state_fails_closed() {
    reset_fixture
    sleep 30 &
    child_pid=$!
    child_start=$(process_start_ticks_for_test "${child_pid}")
    owner_boot=$(cat /proc/sys/kernel/random/boot_id)
    write_shell_xtables_writer_owner \
        2147483646 1 "${child_pid}" "${child_start}" "${owner_boot}"

    if sh -c '
. /src/scripts/lib
process_start_ticks() { return 1; }
claim_shell_xtables_writer_lock
'; then
        kill "${child_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
        fail "unverifiable live participant was guessed stale"
    fi

    grep -qx \
        "flux-shell-xtables-writer-owner-v2 2147483646 1 ${child_pid} ${child_start} ${owner_boot}" \
        "${RUN_ROOT}/xtables-writer.lock/shell-owner" ||
        fail "unverifiable participant record was modified"
    kill "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
}

test_native_xtables_writer_marker_always_blocks_shell_recovery() {
    reset_fixture
    write_shell_xtables_writer_owner 2147483646 1 2147483647 1 \
        "$(cat /proc/sys/kernel/random/boot_id)"
    printf 'native marker\n' >"${RUN_ROOT}/xtables-writer.lock/native-owner"

    if sh /src/scripts/tproxy invalid; then
        fail "shell writer crossed a native writer marker"
    fi

    [ -f "${RUN_ROOT}/xtables-writer.lock/native-owner" ] ||
        fail "shell recovery removed the native writer marker"
    [ -f "${RUN_ROOT}/xtables-writer.lock/shell-owner" ] ||
        fail "shell recovery modified a mixed-owner lock"
}

test_terminated_addrsync_exits_before_readiness_recheck() {
    reset_fixture
    cat >"${FLUX_ROOT}/bin/addrsyncd" <<'EOF'
#!/usr/bin/sh
action="${5:-}"
case "${action}" in
status)
    if [ -e /data/adb/flux/run/addrsync-initial-status ]; then
        : >/data/adb/flux/run/addrsync-post-signal-status
        printf 'running pid=4242\n'
    else
        : >/data/adb/flux/run/addrsync-initial-status
        printf 'stopped\n'
    fi
    ;;
run)
    : >/data/adb/flux/run/addrsync-signal-command-started
    while [ ! -e /data/adb/flux/run/addrsync-signal-command-release ]; do
        sleep 0.01
    done
    ;;
*) exit 0 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/addrsyncd"
    cat >"${RUN_ROOT}/addrsync-signal-runner.sh" <<'EOF'
#!/usr/bin/sh
printf '%s\n' "$$" >/data/adb/flux/run/addrsync-signal-pid
exec sh /src/scripts/addrsync start
EOF
    chmod 0755 "${RUN_ROOT}/addrsync-signal-runner.sh"

    (
        wait_for_test_file "${RUN_ROOT}/addrsync-signal-pid" "addrsync signal pid"
        wait_for_test_file \
            "${RUN_ROOT}/addrsync-signal-command-started" "blocked addrsync startup"
        if ! kill -TERM "$(cat "${RUN_ROOT}/addrsync-signal-pid")"; then
            : >"${RUN_ROOT}/addrsync-signal-command-release"
            exit 1
        fi
        : >"${RUN_ROOT}/addrsync-signal-command-release"
    ) &
    signal_helper=$!
    addrsync_rc=0
    sh "${RUN_ROOT}/addrsync-signal-runner.sh" || addrsync_rc=$?
    wait "${signal_helper}" || fail "addrsync signal helper failed"

    [ "${addrsync_rc}" -eq 143 ] ||
        fail "terminated addrsync returned ${addrsync_rc}, expected 143"
    [ ! -e "${RUN_ROOT}/addrsync-post-signal-status" ] ||
        fail "terminated addrsync performed a post-signal readiness check"
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "terminated direct addrsync retained its writer lock"
}

test_terminated_tproxy_exits_before_post_signal_mutation() {
    reset_fixture
    printf 'cleanup\n' >"${RUN_ROOT}/active_cleanup_ipv6"
    cat >"/data/adb/magisk/iptables-restore" <<'EOF'
#!/usr/bin/sh
: >/data/adb/flux/run/tproxy-signal-command-started
while [ ! -e /data/adb/flux/run/tproxy-signal-command-release ]; do
    sleep 0.01
done
exit 0
EOF
    cat >"/data/adb/magisk/ip" <<'EOF'
#!/usr/bin/sh
case "$*" in
    *"rule del"* | *"route del"*) exit 1 ;;
    *"rule add"* | *"route replace"*)
        : >/data/adb/flux/run/tproxy-post-signal-mutation
        exit 0
        ;;
    *) exit 1 ;;
esac
EOF
    chmod 0755 /data/adb/magisk/iptables-restore /data/adb/magisk/ip
    cat >"${RUN_ROOT}/tproxy-signal-runner.sh" <<'EOF'
#!/usr/bin/sh
printf '%s\n' "$$" >/data/adb/flux/run/tproxy-signal-pid
export PROXY_IPV6=0
export RULE_BACKEND=restore
export BYPASS_SET_BACKEND=none
export PROXY_MODE=tproxy
export MARK_MASK=0xff
export PERFORMANCE_MODE=0
export BLOCK_QUIC=0
export PRIVATE_DNS_GUARD=0
export IPV6_FORCE_DISABLE=0
export VENDOR_FIX_PROFILE=none
export HOTSPOT_FIX=0
export PROXY_PORT=1536
export CORE_USER=root
export CORE_GROUP=root
export FAKEIP_V4_RANGE=198.18.0.0/15
export FAKEIP_V6_RANGE=fc00::/18
exec sh /src/scripts/tproxy start
EOF
    chmod 0755 "${RUN_ROOT}/tproxy-signal-runner.sh"

    (
        wait_for_test_file "${RUN_ROOT}/tproxy-signal-pid" "tproxy signal pid"
        wait_for_test_file \
            "${RUN_ROOT}/tproxy-signal-command-started" "blocked tproxy mutation"
        kill -TERM "$(cat "${RUN_ROOT}/tproxy-signal-pid")"
        : >"${RUN_ROOT}/tproxy-signal-command-release"
    ) &
    signal_helper=$!
    tproxy_rc=0
    sh "${RUN_ROOT}/tproxy-signal-runner.sh" || tproxy_rc=$?
    wait "${signal_helper}" || fail "tproxy signal helper failed"

    [ "${tproxy_rc}" -eq 143 ] ||
        fail "terminated tproxy returned ${tproxy_rc}, expected 143"
    [ ! -e "${RUN_ROOT}/tproxy-post-signal-mutation" ] ||
        fail "terminated tproxy executed a post-signal mutation"
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "terminated direct tproxy retained its writer lock"
}

test_interrupted_dispatcher_exits_before_post_signal_tproxy() {
    reset_fixture
    write_stub addrsync '
. /data/adb/flux/scripts/lib
inherit_shell_xtables_writer_lock || exit 90
trap '\''release_shell_xtables_writer_lock'\'' EXIT
printf "addrsync:%s\n" "$*" >>/data/adb/flux/run/test-calls
release_shell_xtables_writer_lock || exit 91
trap - EXIT
: >/data/adb/flux/run/dispatcher-addrsync-finished
exit 0'
    write_stub core '
while [ ! -e /data/adb/flux/run/dispatcher-addrsync-finished ]; do
    sleep 0.01
done
: >/data/adb/flux/run/dispatcher-signal-command-started
while [ ! -e /data/adb/flux/run/dispatcher-signal-command-release ]; do
    sleep 0.01
done
exit 0'
    write_stub tproxy '
: >/data/adb/flux/run/dispatcher-post-signal-mutation
printf "tproxy:%s\n" "$*" >>/data/adb/flux/run/test-calls
exit 0'
    cat >"${RUN_ROOT}/dispatcher-signal-runner.sh" <<'EOF'
#!/usr/bin/sh
printf '%s\n' "$$" >/data/adb/flux/run/dispatcher-signal-pid
FLUXD_BRIDGE=1 exec sh /data/adb/flux/scripts/dispatcher start
EOF
    chmod 0755 "${RUN_ROOT}/dispatcher-signal-runner.sh"
    : >"${CALLS_FILE}"

    (
        wait_for_test_file "${RUN_ROOT}/dispatcher-signal-pid" "dispatcher signal pid"
        wait_for_test_file \
            "${RUN_ROOT}/dispatcher-signal-command-started" "blocked dispatcher child"
        kill -INT "$(cat "${RUN_ROOT}/dispatcher-signal-pid")"
        : >"${RUN_ROOT}/dispatcher-signal-command-release"
    ) &
    signal_helper=$!
    dispatcher_rc=0
    sh "${RUN_ROOT}/dispatcher-signal-runner.sh" || dispatcher_rc=$?
    wait "${signal_helper}" || fail "dispatcher signal helper failed"

    [ "${dispatcher_rc}" -eq 130 ] ||
        fail "interrupted dispatcher returned ${dispatcher_rc}, expected 130"
    [ ! -e "${RUN_ROOT}/dispatcher-post-signal-mutation" ] ||
        fail "interrupted dispatcher invoked tproxy after its signal"
    assert_not_called tproxy
    [ ! -e "${RUN_ROOT}/xtables-writer.lock" ] ||
        fail "interrupted dispatcher retained its writer lock"
    [ ! -e "${RUN_ROOT}/dispatcher.lock" ] ||
        fail "interrupted dispatcher retained its dispatch lock"
}

test_real_tproxy_stop_refuses_to_claim_detach_while_jumps_remain() {
    reset_fixture
    cat >"/data/adb/magisk/iptables" <<'EOF'
#!/usr/bin/sh
case " $* " in
    *" -S "*) exit 0 ;;
    *" -C "*) exit 0 ;;
    *) exit 1 ;;
esac
EOF
    cat >"/data/adb/magisk/iptables-restore" <<'EOF'
#!/usr/bin/sh
exit 0
EOF
    cat >"/data/adb/magisk/ip" <<'EOF'
#!/usr/bin/sh
case "$*" in
    *"rule show"*|*"route show"*) exit 0 ;;
    *) exit 1 ;;
esac
EOF
    chmod 0755 /data/adb/magisk/iptables /data/adb/magisk/iptables-restore /data/adb/magisk/ip
    printf 'FAMILIES=4\n' >"${RUN_ROOT}/active_runtime"
    printf '*mangle\nCOMMIT\n' >"${RUN_ROOT}/active_cleanup_ipv4"

    if PROXY_IPV6=0 MARK_MASK=0xff PROXY_MODE=tproxy BLOCK_QUIC=0 \
        VENDOR_FIX_PROFILE=none TETHERING_FORWARD=0 \
        sh /src/scripts/tproxy stop; then
        fail "tproxy stop claimed success while capture jumps remained"
    fi

    [ -s "${RUN_ROOT}/active_runtime" ] ||
        fail "failed detach discarded active runtime evidence"
    [ -s "${RUN_ROOT}/active_cleanup_ipv4" ] ||
        fail "failed detach discarded cleanup evidence"
}

test_real_addrsync_stop_propagates_stop_failure() {
    reset_fixture
    cat >"${FLUX_ROOT}/bin/addrsyncd" <<'EOF'
#!/usr/bin/sh
action="${5:-}"
case "${action}" in
    status)
        if [ -f /data/adb/flux/run/fake-addrsync-running ]; then
            printf 'running pid=4242\n'
        else
            printf 'stopped\n'
        fi
        ;;
    stop)
        [ ! -f /data/adb/flux/run/fail-addrsync-stop ] || exit 71
        rm -f /data/adb/flux/run/fake-addrsync-running
        ;;
    *) exit 0 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/addrsyncd"
    : >"${RUN_ROOT}/fake-addrsync-running"
    : >"${RUN_ROOT}/fail-addrsync-stop"
    : >"${RUN_ROOT}/addrsyncd.pid"

    if CORE_TIMEOUT=1 sh /src/scripts/addrsync stop; then
        fail "addrsync stop suppressed the daemon stop failure"
    fi
    [ -f "${RUN_ROOT}/fake-addrsync-running" ] ||
        fail "failed addrsync stop lost running evidence"
    [ -f "${RUN_ROOT}/addrsyncd.pid" ] ||
        fail "failed addrsync stop discarded daemon identity evidence"

    rm -f "${RUN_ROOT}/fail-addrsync-stop"
    CORE_TIMEOUT=1 sh /src/scripts/addrsync stop ||
        fail "addrsync stop did not recover"
    [ ! -e "${RUN_ROOT}/fake-addrsync-running" ] ||
        fail "successful addrsync stop retained running evidence"
    [ ! -e "${RUN_ROOT}/addrsyncd.pid" ] ||
        fail "successful addrsync stop retained daemon identity evidence"
}

test_real_addrsync_start_requires_exact_running_status() {
    reset_fixture
    cat >"${FLUX_ROOT}/bin/addrsyncd" <<'EOF'
#!/usr/bin/sh
action="${5:-}"
case "${action}" in
    status)
        if [ -f /data/adb/flux/run/fake-addrsync-running ]; then
            printf 'running pid=4242\n'
        else
            printf 'stopped\n'
        fi
        ;;
    run)
        printf 'run\n' >>/data/adb/flux/run/addrsyncd-actions
        [ ! -f /data/adb/flux/run/leave-addrsync-stopped ] || exit 0
        : >/data/adb/flux/run/fake-addrsync-running
        ;;
    *) exit 0 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/addrsyncd"

    sh /src/scripts/addrsync start || fail "addrsync did not start from exact stopped state"
    grep -qx 'run' "${RUN_ROOT}/addrsyncd-actions" ||
        fail "addrsync treated exact stopped state as already running"
    sh /src/scripts/addrsync status >"${RUN_ROOT}/addrsync-status" ||
        fail "addrsync rejected exact running state"
    grep -qx 'running pid=4242' "${RUN_ROOT}/addrsync-status" ||
        fail "addrsync did not preserve the trusted running identity"

    rm -f "${RUN_ROOT}/fake-addrsync-running"
    : >"${RUN_ROOT}/leave-addrsync-stopped"
    if sh /src/scripts/addrsync start; then
        fail "addrsync accepted stopped status as startup readiness"
    fi
    [ "$(grep -c '^run$' "${RUN_ROOT}/addrsyncd-actions")" -eq 2 ] ||
        fail "addrsync did not attempt the stopped daemon startup"
}

test_real_addrsync_rejects_config_invalid_status_and_preserves_stop_evidence() {
    reset_fixture
    cat >"${FLUX_ROOT}/bin/addrsyncd" <<'EOF'
#!/usr/bin/sh
action="${5:-}"
case "${action}" in
    status) printf 'stopped(config invalid: missing [rule] section)\n' ;;
    run|stop) printf '%s\n' "${action}" >>/data/adb/flux/run/addrsyncd-actions ;;
    *) exit 0 ;;
esac
EOF
    chmod 0755 "${FLUX_ROOT}/bin/addrsyncd"
    : >"${RUN_ROOT}/addrsyncd.pid"

    if sh /src/scripts/addrsync start; then
        fail "addrsync started with config-invalid status"
    fi
    if sh /src/scripts/addrsync status >/dev/null; then
        fail "addrsync reported config-invalid status as ready"
    fi
    if sh /src/scripts/addrsync stop; then
        fail "addrsync treated config-invalid status as safely stopped"
    fi

    [ -f "${RUN_ROOT}/addrsyncd.pid" ] ||
        fail "config-invalid stop discarded daemon identity evidence"
    [ ! -e "${RUN_ROOT}/addrsyncd-actions" ] ||
        fail "config-invalid status allowed a daemon mutation"
}

test_address_resync_uses_only_the_address_writer() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before address resync failed"
    run_bridge capture-verify "${generation}" || fail "capture-verify before address resync failed"
    run_bridge state-running "${generation}" || fail "state-running before address resync failed"
    : >"${CALLS_FILE}"
    : >"${ENV_CALLS_FILE}"

    run_bridge address-resync || fail "address-resync failed"

    grep -qx 'addrsync:resync' "${CALLS_FILE}" ||
        fail "address-resync did not invoke the address writer"
    grep -q "^addrsync:resync:generation=${generation}:port=1536$" "${ENV_CALLS_FILE}" ||
        fail "address-resync did not load the published generation"
    assert_not_called core
}

test_running_publication_requires_capture_verification() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before verification failed"

    if run_bridge state-running "${generation}"; then
        fail "state-running published before capture verification"
    fi
    ! grep -q '\[RUNNING\]' /data/adb/modules/flux/module.prop ||
        fail "module state became RUNNING before verification"

    run_bridge capture-verify "${generation}" || fail "capture-verify failed"
    [ -s "${RUN_ROOT}/capture.verified" ] || fail "capture-verify marker missing"
    run_bridge state-running "${generation}" || fail "verified state-running failed"
    grep -q '\[RUNNING\]' /data/adb/modules/flux/module.prop ||
        fail "verified state-running did not publish RUNNING"
    grep -qx "${generation} $(cat /proc/sys/kernel/random/boot_id)" "${RUN_ROOT}/engine.active" ||
        fail "state-running did not publish the active generation"
    assert_not_called core
}

test_terminal_state_publication_requires_detached_capture() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before terminal state failed"

    if run_bridge state-failed; then
        fail "state-failed published while capture remained active"
    fi
    ! grep -q '\[FAILED\]' /data/adb/modules/flux/module.prop ||
        fail "FAILED was published before capture detachment"

    run_bridge capture-stop || fail "capture-stop before state-failed failed"
    run_bridge state-failed || fail "detached state-failed failed"
    grep -q '\[FAILED\]' /data/adb/modules/flux/module.prop ||
        fail "state-failed did not publish FAILED"
    [ -s "${RUN_ROOT}/dispatcher.mode" ] || fail "FAILED must retain Rust-owned mode"

    run_bridge state-stopped || fail "detached state-stopped failed"
    grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "state-stopped did not publish STOPPED"
    [ ! -e "${RUN_ROOT}/dispatcher.mode" ] || fail "STOPPED did not release mode lease"
    assert_not_called core
}

test_initial_stopped_publication_is_idempotent_without_a_mode_lease() {
    reset_fixture

    run_bridge state-stopped || fail "initial state-stopped failed"

    grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "initial state-stopped did not publish STOPPED"
    [ ! -e "${RUN_ROOT}/dispatcher.mode" ] ||
        fail "initial state-stopped created a mode lease"
    assert_not_called core
}

test_stopped_publication_rejects_an_unreleasable_mode_lease() {
    reset_fixture
    prepare_generation >/dev/null
    rm -f "${RUN_ROOT}/dispatcher.mode"
    mkdir "${RUN_ROOT}/dispatcher.mode"

    if run_bridge state-stopped; then
        fail "state-stopped claimed success with an unreleasable mode lease"
    fi

    ! grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "STOPPED was published before the ownership lease was released"
    [ -d "${RUN_ROOT}/dispatcher.mode" ] ||
        fail "failed state-stopped discarded ownership evidence"
}

test_startup_recover_detaches_same_boot_rust_capture_before_publishing_stopped() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before recovery failed"
    run_bridge capture-verify "${generation}" || fail "capture-verify before recovery failed"
    run_bridge state-running "${generation}" || fail "state-running before recovery failed"
    : >"${CALLS_FILE}"
    : >"${ENV_CALLS_FILE}"

    run_bridge startup-recover || fail "startup-recover failed"

    cat >"${RUN_ROOT}/expected-calls" <<'EOF'
tproxy:stop
addrsync:stop
EOF
    assert_file_equals "${RUN_ROOT}/expected-calls" "${CALLS_FILE}"
    grep -q "^tproxy:stop:generation=${generation}:port=1536:cache=${GENERATIONS_ROOT}/${generation}/cache_rules_ipv4$" "${ENV_CALLS_FILE}" ||
        fail "startup recovery did not bind cleanup to the stale capture generation"
    [ ! -e "${RUN_ROOT}/capture.active" ] || fail "startup recovery retained active capture"
    [ ! -e "${RUN_ROOT}/capture.verified" ] || fail "startup recovery retained verified capture"
    [ ! -e "${RUN_ROOT}/engine.active" ] || fail "startup recovery retained active engine generation"
    [ ! -e "${RUN_ROOT}/engine.previous" ] || fail "startup recovery retained previous engine generation"
    [ ! -e "${RUN_ROOT}/active_runtime" ] || fail "startup recovery retained capture runtime evidence"
    [ ! -e "${RUN_ROOT}/active_cleanup_ipv4" ] || fail "startup recovery retained capture cleanup evidence"
    [ ! -e "${RUN_ROOT}/dispatcher.mode" ] || fail "startup recovery retained Rust ownership"
    grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "startup recovery did not publish STOPPED"
    assert_not_called core
}

test_startup_recover_quarantines_a_busybox_generation_after_detach() {
    reset_fixture
    sed -i 's/^CORE_USER=.*/CORE_USER=1000/' "${FLUX_ROOT}/cache/cache_config"
    sed -i 's/^CORE_GROUP=.*/CORE_GROUP=3003/' "${FLUX_ROOT}/cache/cache_config"
    printf '#!/usr/bin/sh\nexit 0\n' >/data/adb/magisk/busybox
    chmod 0755 /data/adb/magisk/busybox
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "BusyBox capture-start before recovery failed"
    run_bridge capture-verify "${generation}" || fail "BusyBox capture-verify before recovery failed"
    run_bridge state-running "${generation}" || fail "BusyBox state-running before recovery failed"
    rm -f "${RUN_ROOT}/engine.active"

    if run_bridge startup-recover; then
        fail "startup-recover claimed a BusyBox survivor was contained"
    fi

    [ ! -e "${RUN_ROOT}/capture.active" ] || fail "BusyBox quarantine retained capture"
    [ ! -e "${RUN_ROOT}/active_runtime" ] || fail "BusyBox quarantine retained runtime capture"
    [ -s "${RUN_ROOT}/dispatcher.mode" ] || fail "BusyBox quarantine released Rust ownership"
    [ -s "${RUN_ROOT}/engine.active" ] || fail "BusyBox quarantine discarded engine identity"
    grep -q '\[FAILED\]' /data/adb/modules/flux/module.prop ||
        fail "BusyBox quarantine did not publish FAILED after detachment"
    ! grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "BusyBox quarantine incorrectly published STOPPED"
    if run_bridge startup-recover; then
        fail "repeated startup-recover released a quarantined BusyBox generation"
    fi
}

test_startup_recover_quarantines_a_pre_capture_busybox_generation() {
    reset_fixture
    sed -i 's/^CORE_USER=.*/CORE_USER=1000/' "${FLUX_ROOT}/cache/cache_config"
    sed -i 's/^CORE_GROUP=.*/CORE_GROUP=3003/' "${FLUX_ROOT}/cache/cache_config"
    printf '#!/usr/bin/sh\nexit 0\n' >/data/adb/magisk/busybox
    chmod 0755 /data/adb/magisk/busybox
    generation=$(prepare_generation)

    if run_bridge startup-recover; then
        fail "startup-recover released a pre-capture BusyBox generation"
    fi

    grep -qx "${generation} $(cat /proc/sys/kernel/random/boot_id)" "${RUN_ROOT}/engine.active" ||
        fail "pre-capture BusyBox quarantine did not persist its generation"
    [ -s "${RUN_ROOT}/dispatcher.mode" ] || fail "pre-capture BusyBox quarantine released ownership"
    grep -q '\[FAILED\]' /data/adb/modules/flux/module.prop ||
        fail "pre-capture BusyBox quarantine did not publish FAILED"
}

test_startup_recover_quarantines_a_prepared_busybox_reload_candidate() {
    reset_fixture
    active_generation=$(prepare_generation)
    run_bridge capture-start "${active_generation}" || fail "direct capture-start before BusyBox reload failed"
    run_bridge capture-verify "${active_generation}" || fail "direct capture-verify before BusyBox reload failed"
    run_bridge state-running "${active_generation}" || fail "direct state-running before BusyBox reload failed"
    sed -i 's/^CORE_USER=.*/CORE_USER=1000/' "${FLUX_ROOT}/cache/cache_config"
    sed -i 's/^CORE_GROUP=.*/CORE_GROUP=3003/' "${FLUX_ROOT}/cache/cache_config"
    printf '#!/usr/bin/sh\nexit 0\n' >/data/adb/magisk/busybox
    chmod 0755 /data/adb/magisk/busybox
    candidate_generation=$(prepare_generation)

    if run_bridge startup-recover; then
        fail "startup-recover trusted the old direct generation over a prepared BusyBox candidate"
    fi

    grep -qx "${candidate_generation} $(cat /proc/sys/kernel/random/boot_id)" "${RUN_ROOT}/engine.active" ||
        fail "BusyBox reload quarantine retained the wrong generation"
    [ ! -e "${RUN_ROOT}/capture.active" ] || fail "BusyBox reload quarantine retained capture"
    [ -s "${RUN_ROOT}/dispatcher.mode" ] || fail "BusyBox reload quarantine released ownership"
}

test_startup_recover_detaches_markerless_partial_activation() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before markerless recovery failed"
    rm -f "${RUN_ROOT}/capture.active"
    : >"${CALLS_FILE}"
    : >"${ENV_CALLS_FILE}"

    run_bridge startup-recover || fail "markerless startup recovery failed"

    cat >"${RUN_ROOT}/expected-calls" <<'EOF'
tproxy:stop
addrsync:stop
EOF
    assert_file_equals "${RUN_ROOT}/expected-calls" "${CALLS_FILE}"
    grep -q "^tproxy:stop:generation=${generation}:port=1536:cache=${GENERATIONS_ROOT}/${generation}/cache_rules_ipv4$" "${ENV_CALLS_FILE}" ||
        fail "markerless recovery did not load the prepared generation"
    [ ! -e "${RUN_ROOT}/active_runtime" ] || fail "markerless recovery retained capture runtime evidence"
    [ ! -e "${RUN_ROOT}/active_cleanup_ipv4" ] || fail "markerless recovery retained cleanup evidence"
    [ ! -e "${RUN_ROOT}/dispatcher.mode" ] || fail "markerless recovery retained Rust ownership"
    grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "markerless recovery did not publish STOPPED"
    assert_not_called core
}

test_startup_recover_is_idempotent_without_ownership_or_capture_evidence() {
    reset_fixture

    run_bridge startup-recover || fail "unowned startup-recover failed"

    grep -q '\[STOPPED\]' /data/adb/modules/flux/module.prop ||
        fail "unowned startup recovery did not publish STOPPED"
    [ ! -e "${RUN_ROOT}/dispatcher.mode" ] ||
        fail "unowned startup recovery created a mode lease"
    assert_not_called core
}

test_startup_recover_preserves_rust_ownership_when_detach_cannot_be_proven() {
    reset_fixture
    generation=$(prepare_generation)
    run_bridge capture-start "${generation}" || fail "capture-start before failed recovery failed"
    run_bridge capture-verify "${generation}" || fail "capture-verify before failed recovery failed"
    run_bridge state-running "${generation}" || fail "state-running before failed recovery failed"
    write_stub tproxy '
. /data/adb/flux/scripts/lib
printf "tproxy:%s\n" "$*" >>/data/adb/flux/run/test-calls
[ "${1:-}" != stop ] || exit 71
exit 0'
    : >"${CALLS_FILE}"

    if run_bridge startup-recover; then
        fail "startup-recover claimed success after capture cleanup failed"
    fi

    grep -qx 'tproxy:stop' "${CALLS_FILE}" || fail "startup recovery did not attempt capture cleanup"
    grep -qx 'addrsync:stop' "${CALLS_FILE}" || fail "startup recovery did not stop address synchronization"
    [ -s "${RUN_ROOT}/capture.active" ] || fail "failed startup recovery lost active capture evidence"
    [ -s "${RUN_ROOT}/dispatcher.mode" ] || fail "failed startup recovery released Rust ownership"
    grep -q '\[RUNNING\]' /data/adb/modules/flux/module.prop ||
        fail "failed startup recovery published a terminal state"
    assert_not_called core
}

test_startup_recover_rejects_live_legacy_ownership_without_mutation() {
    reset_fixture
    run_bridge start || fail "legacy start before recovery rejection failed"
    cp "${RUN_ROOT}/dispatcher.mode" "${RUN_ROOT}/legacy-mode-before-recovery"
    cp /data/adb/modules/flux/module.prop "${RUN_ROOT}/module-prop-before-recovery"
    : >"${CALLS_FILE}"

    if run_bridge startup-recover; then
        fail "startup-recover mutated a live legacy-owned runtime"
    fi

    [ ! -s "${CALLS_FILE}" ] || fail "startup recovery invoked a legacy-owned component"
    assert_file_equals "${RUN_ROOT}/legacy-mode-before-recovery" "${RUN_ROOT}/dispatcher.mode"
    assert_file_equals "${RUN_ROOT}/module-prop-before-recovery" /data/adb/modules/flux/module.prop
}

test_legacy_and_rust_owned_verbs_cannot_mix() {
    reset_fixture
    run_bridge prepare || fail "Rust-owned prepare failed"
    : >"${CALLS_FILE}"
    if run_bridge start; then
        fail "legacy start mixed into Rust-owned mode"
    fi
    assert_not_called core

    reset_fixture
    run_bridge start || fail "legacy rollback start failed"
    if run_bridge prepare; then
        fail "Rust-owned prepare mixed into legacy mode"
    fi
    grep -q '^core:start$' "${CALLS_FILE}" || fail "legacy start did not retain core rollback"
    [ ! -e "${RUN_ROOT}/engine.manifest" ] || fail "rejected mixed prepare retained manifest"
}

test_prepare_writes_exact_direct_manifest_without_core
test_real_init_uses_rust_renderer_and_snapshots_one_package_inventory
test_real_init_attests_and_snapshots_one_dual_family_rule_set
test_real_init_rebuilds_before_reusing_a_stale_generation_receipt
test_serialized_cache_preview_bootstraps_without_a_generation_receipt
test_cache_preview_cannot_overlap_generation_attestation
test_real_init_keeps_explicit_shell_renderer_rollback_for_legacy_owner
test_legacy_restart_prepares_before_stopping_the_active_runtime
test_failed_rust_render_preserves_the_active_generation
test_failed_rust_attestation_preserves_the_active_generation
test_prepare_removes_stale_manifest_on_failure
test_prepare_creates_distinct_immutable_generation_artifacts
test_previous_generation_can_be_selected_after_newer_prepare
test_generation_mismatch_is_rejected_for_verification_and_publication
test_running_publication_retains_only_current_and_previous_generations
test_prepare_writes_exact_busybox_manifest
test_prepare_rejects_tun_before_init_or_manifest
test_prepare_rejects_missing_proxy_mode_without_artifacts
test_prepare_revalidates_proxy_mode_generated_by_init
test_active_tproxy_prepare_rejects_tun_without_disturbance
test_rust_owned_config_build_skips_unpinned_sing_box_check
test_prepare_rejects_missing_xt_owner_before_init_or_generation_publication
test_prepare_revalidates_xt_owner_generated_by_init
test_capture_start_owns_only_addrsync_and_tproxy
test_capture_start_compensates_partial_failure
test_capture_start_preserves_retry_evidence_when_compensation_fails
test_capture_stop_is_ordered_and_idempotent
test_native_xtables_lease_blocks_dispatcher_shell_writers
test_native_xtables_lease_blocks_legacy_start_before_network_mutation
test_native_xtables_lease_blocks_ambient_internal_writer_state
test_native_xtables_lease_blocks_legacy_stop_before_network_mutation
test_native_xtables_lease_blocks_legacy_restart_before_network_mutation
test_native_xtables_lease_blocks_legacy_failure_cleanup_mutation
test_native_xtables_lease_blocks_direct_tproxy_mutation
test_native_xtables_lease_blocks_direct_addrsync_mutation_but_not_status
test_xtables_transition_lock_blocks_shell_writers
test_spoofed_inherited_xtables_writer_metadata_is_rejected
test_valid_parent_bound_xtables_writer_metadata_reaches_tproxy
test_dead_stale_child_for_same_live_parent_can_be_replaced
test_live_child_record_cannot_be_replaced
test_nonparticipant_cannot_forge_parent_release_state
test_nonparticipant_cannot_forge_child_release_state
test_sigkilled_child_keeps_live_parent_busy_until_parent_release
test_sigkilled_parent_keeps_live_child_busy_until_child_release
test_sigkilled_dispatcher_keeps_live_addrsync_phase_fenced
test_both_dead_shell_xtables_writer_participants_are_recovered
test_dead_shell_xtables_writer_lock_is_recovered_before_direct_claim
test_pid_reused_shell_xtables_writer_participants_are_recovered
test_previous_boot_shell_xtables_writer_lock_is_recovered
test_malformed_shell_xtables_writer_record_fails_closed
test_unverifiable_live_participant_state_fails_closed
test_native_xtables_writer_marker_always_blocks_shell_recovery
test_terminated_addrsync_exits_before_readiness_recheck
test_terminated_tproxy_exits_before_post_signal_mutation
test_interrupted_dispatcher_exits_before_post_signal_tproxy
test_real_tproxy_stop_refuses_to_claim_detach_while_jumps_remain
test_real_addrsync_stop_propagates_stop_failure
test_real_addrsync_start_requires_exact_running_status
test_real_addrsync_rejects_config_invalid_status_and_preserves_stop_evidence
test_address_resync_uses_only_the_address_writer
test_running_publication_requires_capture_verification
test_terminal_state_publication_requires_detached_capture
test_initial_stopped_publication_is_idempotent_without_a_mode_lease
test_stopped_publication_rejects_an_unreleasable_mode_lease
test_startup_recover_detaches_same_boot_rust_capture_before_publishing_stopped
test_startup_recover_quarantines_a_busybox_generation_after_detach
test_startup_recover_quarantines_a_pre_capture_busybox_generation
test_startup_recover_quarantines_a_prepared_busybox_reload_candidate
test_startup_recover_detaches_markerless_partial_activation
test_startup_recover_is_idempotent_without_ownership_or_capture_evidence
test_startup_recover_preserves_rust_ownership_when_detach_cannot_be_proven
test_startup_recover_rejects_live_legacy_ownership_without_mutation
test_legacy_and_rust_owned_verbs_cannot_mix
printf 'dispatcher Flux-owned shell tests: PASS\n'
