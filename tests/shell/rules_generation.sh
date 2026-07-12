#!/usr/bin/sh

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

printf 'rules generation shell tests: PASS\n'
