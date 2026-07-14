#!/usr/bin/sh
# shellcheck disable=SC2030,SC2031

set -eu

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
readonly TEST_DIR
REPO_ROOT=$(CDPATH='' cd -- "${TEST_DIR}/../.." && pwd)
readonly REPO_ROOT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equals() {
    expected="${1}"
    actual="${2}"
    label="${3}"

    [ "${actual}" = "${expected}" ] || {
        printf '%s\n' '--- expected ---' >&2
        printf '%s\n' "${expected}" >&2
        printf '%s\n' '--- actual ---' >&2
        printf '%s\n' "${actual}" >&2
        fail "${label}"
    }
}

. "${REPO_ROOT}/scripts/rules"

# These globals are the configuration contract consumed by the sourced helpers.
# shellcheck disable=SC2034
KFEAT_OWNER=1
# shellcheck disable=SC2034
KFEAT_MARK=0
# shellcheck disable=SC2034
CORE_USER=1000
# shellcheck disable=SC2034
CORE_GROUP=1000
# shellcheck disable=SC2034
ROUTING_MARK=""
# shellcheck disable=SC2034
APP_USER_SCOPE=owner
# shellcheck disable=SC2034
APP_USER_LIST=""
PACKAGES_LIST="${TEST_DIR}/does-not-exist"

ipv4_bypass=$(_build_bypass_ip_rules "" 4)
printf '%s\n' "${ipv4_bypass}" |
    grep -Fqx -- '-A BYP_Z6 -d 100.64.0.0/10 -j ACTION_BYPASS' ||
    fail "IPv4 bypass rules omitted RFC 6598 CGNAT"
if printf '%s\n' "${ipv4_bypass}" | grep -Fq -- '100.0.0.0/8'; then
    fail "IPv4 bypass rules retained the overbroad 100.0.0.0/8 prefix"
fi

APP_LIST=""
mode_zero=$(_build_app_rules "" 0)
assert_equals \
    '-A APP_CHAIN -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS
-A APP_CHAIN -j RETURN' \
    "${mode_zero}" \
    "mode zero must preserve the Proxy Engine owner bypass"

mode_zero_v6=$(_build_app_rules "6" 0)
assert_equals \
    '-A APP_CHAIN6 -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS6
-A APP_CHAIN6 -j RETURN' \
    "${mode_zero_v6}" \
    "IPv6 mode zero must preserve the Proxy Engine owner bypass"

allowlist=$(_build_app_rules "" 2)
assert_equals \
    '-A APP_CHAIN -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS
-A APP_CHAIN -j ACCEPT' \
    "${allowlist}" \
    "empty allowlist must proxy zero applications"

denylist=$(_build_app_rules "" 1)
assert_equals \
    '-A APP_CHAIN -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS
-A APP_CHAIN -j ACTION_PROXY_OUT' \
    "${denylist}" \
    "empty denylist must proxy every otherwise eligible application"

allowlist_v6=$(_build_app_rules "6" 2)
assert_equals \
    '-A APP_CHAIN6 -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS6
-A APP_CHAIN6 -j ACCEPT' \
    "${allowlist_v6}" \
    "IPv6 empty allowlist must proxy zero applications"

# shellcheck disable=SC2034
MOBILE_INTERFACE=""
# shellcheck disable=SC2034
WIFI_INTERFACE=""
# shellcheck disable=SC2034
HOTSPOT_INTERFACE=""
# shellcheck disable=SC2034
USB_INTERFACE=""
# shellcheck disable=SC2034
PROXY_MOBILE=1
# shellcheck disable=SC2034
PROXY_WIFI=1
# shellcheck disable=SC2034
PROXY_HOTSPOT=1
# shellcheck disable=SC2034
PROXY_USB=1

mode_zero_output=$(_build_chain_rules \
    "PROXY_OUTPUT" "ACTION_PROXY_OUT" "-o" "" 0)
assert_equals \
    '-A PROXY_OUTPUT -j BYPASS_IP
-A PROXY_OUTPUT -j APP_CHAIN
-A PROXY_OUTPUT -j ACTION_PROXY_OUT' \
    "${mode_zero_output}" \
    "mode zero OUTPUT must run the engine bypass before proxy action"

mode_zero_output_v6=$(_build_chain_rules \
    "PROXY_OUTPUT6" "ACTION_PROXY_OUT6" "-o" "" 0)
assert_equals \
    '-A PROXY_OUTPUT6 -j BYPASS_IP6
-A PROXY_OUTPUT6 -j APP_CHAIN6
-A PROXY_OUTPUT6 -j ACTION_PROXY_OUT6' \
    "${mode_zero_output_v6}" \
    "IPv6 mode zero OUTPUT must run the engine bypass before proxy action"

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM
PACKAGES_LIST="${tmp_dir}/packages.list"
printf '%s\n' 'com.example.app 10123' >"${PACKAGES_LIST}"
# shellcheck disable=SC2034
APP_LIST="com.example.app"

populated_allowlist=$(_build_app_rules "" 2)
assert_equals \
    '-A APP_CHAIN -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS
-A APP_CHAIN -m owner --uid-owner 10123 -j ACTION_PROXY_OUT
-A APP_CHAIN -j ACCEPT' \
    "${populated_allowlist}" \
    "populated allowlist changed rule semantics"

# Associative-array iteration differs across awk implementations. User IDs are
# semantic sets, so the oracle emits them in canonical numeric order.
# shellcheck disable=SC2034
APP_USER_SCOPE=list
# shellcheck disable=SC2034
APP_USER_LIST="10 2 10"
multi_user_allowlist=$(_build_app_rules "" 2)
assert_equals \
    '-A APP_CHAIN -m owner --uid-owner 1000 --gid-owner 1000 -j ACTION_BYPASS
-A APP_CHAIN -m owner --uid-owner 210123 -j ACTION_PROXY_OUT
-A APP_CHAIN -m owner --uid-owner 1010123 -j ACTION_PROXY_OUT
-A APP_CHAIN -j ACCEPT' \
    "${multi_user_allowlist}" \
    "multi-user rules must use canonical numeric user order"

# Excluded interfaces retain configured order; indexed iteration avoids
# implementation-defined associative-array order.
# shellcheck disable=SC2034
MOBILE_INTERFACE=""
# shellcheck disable=SC2034
WIFI_INTERFACE=""
# shellcheck disable=SC2034
HOTSPOT_INTERFACE=""
# shellcheck disable=SC2034
USB_INTERFACE=""
ordered_exclusions=$(_build_chain_rules \
    "PROXY_PREROUTING" "ACTION_PROXY_PRE" "-i" "wlan+ rmnet+ wlan+" 1)
assert_equals \
    '-A PROXY_PREROUTING -j BYPASS_IP
-A PROXY_PREROUTING -i lo -j ACCEPT
-A PROXY_PREROUTING -i wlan+ -j ACCEPT
-A PROXY_PREROUTING -i rmnet+ -j ACCEPT
-A PROXY_PREROUTING -i wlan+ -j ACCEPT
-A PROXY_PREROUTING -j ACCEPT' \
    "${ordered_exclusions}" \
    "excluded interfaces must retain configured order"

if command -v gawk >/dev/null 2>&1 && command -v mawk >/dev/null 2>&1; then
    gawk_dir="${tmp_dir}/gawk"
    mawk_dir="${tmp_dir}/mawk"
    mkdir -p "${gawk_dir}" "${mawk_dir}"
    ln -s "$(command -v gawk)" "${gawk_dir}/awk"
    ln -s "$(command -v mawk)" "${mawk_dir}/awk"

    gawk_multi_user=$(PATH="${gawk_dir}:${PATH}"; export PATH; _build_app_rules "" 2)
    mawk_multi_user=$(PATH="${mawk_dir}:${PATH}"; export PATH; _build_app_rules "" 2)
    assert_equals \
        "${gawk_multi_user}" \
        "${mawk_multi_user}" \
        "multi-user rule bytes differ between gawk and mawk"

    gawk_exclusions=$(PATH="${gawk_dir}:${PATH}"; export PATH; _build_chain_rules \
        "PROXY_PREROUTING" "ACTION_PROXY_PRE" "-i" "wlan+ rmnet+ wlan+" 1)
    mawk_exclusions=$(PATH="${mawk_dir}:${PATH}"; export PATH; _build_chain_rules \
        "PROXY_PREROUTING" "ACTION_PROXY_PRE" "-i" "wlan+ rmnet+ wlan+" 1)
    assert_equals \
        "${gawk_exclusions}" \
        "${mawk_exclusions}" \
        "excluded-interface rule bytes differ between gawk and mawk"
fi

printf 'rules generation shell tests: PASS\n'
