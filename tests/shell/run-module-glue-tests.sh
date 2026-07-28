#!/usr/bin/env sh

set -eu

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

skip_or_fail() {
    message="${1}"
    if [ "${FLUX_MODULE_GLUE_TESTS_REQUIRED}" = "1" ]; then
        fail "${message}"
    fi
    printf 'SKIP: %s\n' "${message}" >&2
    exit 0
}

[ "$#" -eq 0 ] || fail "this wrapper does not accept arguments"

FLUX_MODULE_GLUE_TESTS_REQUIRED="${FLUX_MODULE_GLUE_TESTS_REQUIRED:-0}"
case "${FLUX_MODULE_GLUE_TESTS_REQUIRED}" in
0 | 1) ;;
*) fail "FLUX_MODULE_GLUE_TESTS_REQUIRED must be 0 or 1" ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) ||
    fail "cannot resolve the test directory"
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd -P) ||
    fail "cannot resolve the repository root"
readonly SCRIPT_DIR REPO_ROOT

BWRAP_COMMAND="${BWRAP:-bwrap}"
BWRAP_BIN=$(command -v "${BWRAP_COMMAND}" 2>/dev/null || true)
[ -n "${BWRAP_BIN}" ] || skip_or_fail "bubblewrap is unavailable"
[ -x "${BWRAP_BIN}" ] || skip_or_fail "bubblewrap is not executable: ${BWRAP_BIN}"
command -v zip >/dev/null 2>&1 || skip_or_fail "zip is unavailable"

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

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM
fixture="${tmp_dir}/fixture"
data_root="${tmp_dir}/data"
helper_bin="${tmp_dir}/helpers"
mkdir -p \
    "${fixture}/bin" \
    "${fixture}/conf" \
    "${fixture}/webroot" \
    "${data_root}/adb/modules/flux" \
    "${data_root}/adb/service.d" \
    "${data_root}/adb/ksu/service.d" \
    "${helper_bin}"

printf '%s\n' \
    'id=flux' \
    'name=Flux' \
    'version=v1.0.0' \
    'versionCode=1' \
    'author=Flux' \
    'description=fixture' >"${fixture}/module.prop"
printf '<html></html>\n' >"${fixture}/webroot/index.html"
printf 'fixture license\n' >"${fixture}/LICENSE"
printf 'fixture fluxd\n' >"${fixture}/bin/fluxd"
printf 'fixture engine\n' >"${fixture}/bin/sing-box"
printf 'schema = 3\n' >"${fixture}/conf/flux.toml"
printf '{}\n' >"${fixture}/conf/template.json"
printf '{}\n' >"${fixture}/conf/manifest.json"
cp "${REPO_ROOT}/customize.sh" "${fixture}/customize.sh"
cp "${REPO_ROOT}/flux_service.sh" "${fixture}/flux_service.sh"
cp "${REPO_ROOT}/uninstall.sh" "${fixture}/uninstall.sh"
printf 'legacy launcher\n' >"${data_root}/adb/service.d/flux_service.sh"
printf 'legacy launcher\n' >"${data_root}/adb/ksu/service.d/flux_service.sh"

(
    cd "${fixture}"
    zip -qr "${tmp_dir}/module.zip" .
)

run_installer() {
    output_label="${1}"
    set +e
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
        --bind "${data_root}" /data \
        --ro-bind "${REPO_ROOT}" /src \
        --ro-bind "${tmp_dir}/module.zip" /fixture/module.zip \
        --setenv BOOTMODE true \
        --setenv MODPATH /data/adb/modules/flux \
        --setenv ZIPFILE /fixture/module.zip \
        /usr/bin/sh -c '
            ui_print() { :; }
            abort() { exit 77; }
            set_perm_recursive() { :; }
            set_perm() { :; }
            . /src/customize.sh
        ' >"${tmp_dir}/installer-${output_label}.out" \
        2>"${tmp_dir}/installer-${output_label}.err"
    installer_exit=$?
    set -e
}

run_installer fresh
[ "${installer_exit}" -eq 0 ] || fail "fresh native install failed: ${installer_exit}"
for relative in \
    bin/fluxd \
    bin/sing-box \
    conf/flux.toml \
    conf/template.json \
    conf/manifest.json; do
    [ -f "${data_root}/adb/flux/${relative}" ] ||
        fail "fresh install omitted runtime file ${relative}"
done
for relative in module.prop service.sh uninstall.sh webroot/index.html LICENSE; do
    [ -f "${data_root}/adb/modules/flux/${relative}" ] ||
        fail "fresh install omitted module file ${relative}"
done
cmp -s \
    "${REPO_ROOT}/flux_service.sh" \
    "${data_root}/adb/modules/flux/service.sh" ||
    fail "installed service.sh differs from the authoritative source"
[ ! -e "${data_root}/adb/flux/scripts" ] || fail "fresh install created a scripts tree"
[ ! -e "${data_root}/adb/flux/bin/jq" ] || fail "fresh install created jq"
[ ! -e "${data_root}/adb/flux/bin/addrsyncd" ] || fail "fresh install created addrsyncd"
[ ! -e "${data_root}/adb/flux/conf/settings.ini" ] || fail "fresh install created settings.ini"
[ ! -e "${data_root}/adb/flux/conf/addrsyncd.toml" ] || fail "fresh install created addrsyncd.toml"
[ ! -e "${data_root}/adb/service.d/flux_service.sh" ] || fail "legacy Magisk launcher survived"
[ ! -e "${data_root}/adb/ksu/service.d/flux_service.sh" ] || fail "legacy KernelSU launcher survived"

run_installer existing
[ "${installer_exit}" -eq 77 ] ||
    fail "existing runtime root did not fail closed: ${installer_exit}"
[ "$(cat "${data_root}/adb/flux/bin/fluxd")" = "fixture fluxd" ] ||
    fail "failed reinstall changed the existing runtime payload"

cat >"${helper_bin}/getprop" <<'EOF'
#!/usr/bin/sh
[ "${1:-}" = "sys.boot_completed" ] || exit 2
printf '1\n'
EOF
cat >"${helper_bin}/sleep" <<'EOF'
#!/usr/bin/sh
exit 0
EOF
cat >"${data_root}/adb/flux/bin/fluxd" <<'EOF'
#!/usr/bin/sh
printf '%s\n' "$*" >>/data/adb/flux/service.calls
calls=$(wc -l </data/adb/flux/service.calls)
case "${FLUX_SERVICE_TEST_MODE}" in
recover) [ "${calls}" -ge 3 ] && exit 0; exit 9 ;;
fail) exit 7 ;;
*) exit 98 ;;
esac
EOF
chmod 0700 \
    "${helper_bin}/getprop" \
    "${helper_bin}/sleep" \
    "${data_root}/adb/flux/bin/fluxd"

run_service() {
    service_mode="${1}"
    : >"${data_root}/adb/flux/service.calls"
    set +e
    "${BWRAP_BIN}" \
        --tmpfs / \
        --ro-bind /usr /usr \
        --ro-bind /etc /etc \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --bind "${data_root}" /data \
        --ro-bind "${REPO_ROOT}" /src \
        --ro-bind "${helper_bin}" /helpers \
        --setenv PATH /helpers:/usr/bin \
        --setenv FLUX_SERVICE_TEST_MODE "${service_mode}" \
        /usr/bin/sh /src/flux_service.sh \
        >"${tmp_dir}/service-${service_mode}.out" \
        2>"${tmp_dir}/service-${service_mode}.err"
    service_exit=$?
    set -e
}

run_service recover
[ "${service_exit}" -eq 0 ] || fail "recovering watchdog failed: ${service_exit}"
[ "$(wc -l <"${data_root}/adb/flux/service.calls")" -eq 3 ] ||
    fail "recovering watchdog did not stop after the successful third launch"
[ "$(sort -u "${data_root}/adb/flux/service.calls")" = "daemon" ] ||
    fail "watchdog invoked a command other than fluxd daemon"

run_service fail
[ "${service_exit}" -eq 7 ] || fail "bounded watchdog changed final failure: ${service_exit}"
[ "$(wc -l <"${data_root}/adb/flux/service.calls")" -eq 5 ] ||
    fail "bounded watchdog did not stop at five failed launches"
[ "$(sort -u "${data_root}/adb/flux/service.calls")" = "daemon" ] ||
    fail "failed watchdog invoked a command other than fluxd daemon"

uninstall_calls="${data_root}/adb/flux/uninstall.calls"
cat >"${data_root}/adb/flux/bin/fluxd" <<'EOF'
#!/usr/bin/sh
printf '%s\n' "$*" >>/data/adb/flux/uninstall.calls
case "${1:-}" in
ping) exit "${FLUX_UNINSTALL_TEST_PING_RC}" ;;
stop) exit "${FLUX_UNINSTALL_TEST_STOP_RC}" ;;
cleanup)
    [ "$#" -eq 2 ] && [ "${2}" = "--offline" ] || exit 98
    exit "${FLUX_UNINSTALL_TEST_CLEANUP_RC}"
    ;;
*) exit 99 ;;
esac
EOF
chmod 0700 "${data_root}/adb/flux/bin/fluxd"

run_uninstall_case() {
    uninstall_case="${1}"
    uninstall_ping_rc="${2}"
    uninstall_stop_rc="${3}"
    uninstall_cleanup_rc="${4}"
    : >"${uninstall_calls}"
    set +e
    "${BWRAP_BIN}" \
        --tmpfs / \
        --ro-bind /usr /usr \
        --ro-bind /etc /etc \
        --symlink usr/bin /bin \
        --symlink usr/lib /lib \
        --symlink usr/lib64 /lib64 \
        --proc /proc \
        --dev /dev \
        --bind "${data_root}" /data \
        --ro-bind "${REPO_ROOT}" /src \
        --setenv FLUX_UNINSTALL_TEST_PING_RC "${uninstall_ping_rc}" \
        --setenv FLUX_UNINSTALL_TEST_STOP_RC "${uninstall_stop_rc}" \
        --setenv FLUX_UNINSTALL_TEST_CLEANUP_RC "${uninstall_cleanup_rc}" \
        /usr/bin/sh /src/uninstall.sh \
        >"${tmp_dir}/uninstall-${uninstall_case}.out" \
        2>"${tmp_dir}/uninstall-${uninstall_case}.err"
    uninstall_exit=$?
    set -e
}

run_uninstall_case online 0 0 91
[ "${uninstall_exit}" -eq 0 ] || fail "online uninstall delegation failed: ${uninstall_exit}"
actual_calls=$(cat "${uninstall_calls}")
expected_calls=$(printf 'ping\nstop')
[ "${actual_calls}" = "${expected_calls}" ] ||
    fail "online uninstall did not stop after successful daemon delegation"

run_uninstall_case offline 7 88 0
[ "${uninstall_exit}" -eq 0 ] || fail "offline uninstall delegation failed: ${uninstall_exit}"
actual_calls=$(cat "${uninstall_calls}")
expected_calls=$(printf 'ping\ncleanup --offline')
[ "${actual_calls}" = "${expected_calls}" ] ||
    fail "offline uninstall did not invoke the exact cleanup command"

run_uninstall_case stop-failed 0 9 75
[ "${uninstall_exit}" -eq 75 ] ||
    fail "uninstall did not propagate offline cleanup failure: ${uninstall_exit}"
actual_calls=$(cat "${uninstall_calls}")
expected_calls=$(printf 'ping\nstop\ncleanup --offline')
[ "${actual_calls}" = "${expected_calls}" ] ||
    fail "failed online stop did not fall back to exact offline cleanup"

printf 'native installer, launcher, and uninstall shell tests: PASS\n'
