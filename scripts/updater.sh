#!/system/bin/sh

# ==============================================================================
# [ Flux Subscription Updater - Masterpiece Edition ]
# Description: Industrial-grade node synchronization with atomic deployment.
# ==============================================================================

# Strict error handling (compatible with most Android shells)
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

# ==============================================================================
# [ Core Configuration ]
# ==============================================================================

readonly SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "${SCRIPT_DIR}/const"
. "${SCRIPT_DIR}/log"

readonly LOG_COMPONENT="Updt"

readonly INFRASTRUCTURE_TYPES='["selector","urltest","direct","block","dns"]'

# State management
TMP_CONFIG=""
WORK_DIR=""

# ==============================================================================
# [ Node Processing Rules ] (User Configurable)
# ==============================================================================

# Regex for nodes to exclude (matched against tag/remarks)
EXCLUDE_REMARKS="(expire|traffic|官网|到期|流量|剩余|套餐|重置|联系|群组|通知|平台|网站|时间|建议|反馈|版本|更新)"

# Custom rename rules in JSON format: [{"match": "regex", "replace": "text"}, ...]
RENAME_RULES='[
    {"match":"【(亚洲|北美洲|欧洲|南美洲|非洲|大洋洲|南极洲)】","replace":""},
    {"match":"(家宽|三网|原生|倍率|游戏专线)","replace":""},
    {"match":"【","replace":"["},
    {"match":"】","replace":"]"}
]'

# Default Country Map for grouping
readonly DEFAULT_COUNTRY_MAP='{
  "HK": "港|hk|hongkong|hong kong|🇭🇰",
  "TW": "台|tw|taiwan|🇹🇼",
  "JP": "日本|jp|japan|🇯🇵",
  "SG": "新|sg|singapore|🇸🇬",
  "US": "美|us|usa|united states|america|🇺🇸",
  "KR": "韩|kr|korea|south korea|🇰🇷",
  "UK": "英|uk|gb|united kingdom|britain|🇬🇧",
  "DE": "德|de|germany|🇩🇪",
  "FR": "法|fr|france|🇫🇷",
  "CA": "加|ca|canada|🇨🇦",
  "AU": "澳|au|australia|🇦🇺",
  "RU": "俄|ru|russia|🇷🇺",
  "NL": "荷|nl|netherlands|🇳🇱",
  "IN": "印|in|india|🇮🇳",
  "TR": "土|tr|turkey|türkiye|🇹🇷",
  "IT": "意|it|italy|🇮🇹",
  "CH": "瑞士|ch|switzerland|🇨🇭",
  "SE": "瑞典|se|sweden|🇸🇪",
  "BR": "巴西|br|brazil|🇧🇷",
  "AR": "阿根廷|ar|argentina|🇦🇷",
  "VN": "越|vn|vietnam|🇻🇳",
  "TH": "泰|th|thailand|🇹🇭",
  "PH": "菲|ph|philippines|🇵🇭",
  "MY": "马来|my|malaysia|🇲🇾",
  "ID": "印尼|id|indonesia|🇮🇩",
  "ES": "西班牙|es|spain|🇪🇸",
  "PL": "波兰|pl|poland|🇵🇱",
  "FI": "芬兰|fi|finland|🇫🇮",
  "NO": "挪威|no|norway|🇳🇴",
  "DK": "丹麦|dk|denmark|🇩🇰",
  "AT": "奥地利|at|austria|🇦🇹",
  "BE": "比利时|be|belgium|🇧🇪",
  "IE": "爱尔兰|ie|ireland|🇮🇪",
  "PT": "葡萄牙|pt|portugal|🇵🇹",
  "CZ": "捷克|cz|czech|🇨🇿",
  "GR": "希腊|gr|greece|🇬🇷",
  "IL": "以色列|il|israel|🇮🇱",
  "AE": "阿联酋|ae|uae|dubai|🇦🇪",
  "ZA": "南非|za|south africa|🇿🇦",
  "MX": "墨西哥|mx|mexico|🇲🇽",
  "CL": "智利|cl|chile|🇨🇱",
  "CO": "哥联比亚|co|colombia|🇨🇴",
  "PE": "秘鲁|pe|peru|🇵🇪",
  "NZ": "新西兰|nz|new zealand|🇳🇿",
  "HU": "匈牙利|hu|hungary|🇭🇺",
  "RO": "罗马尼亚|ro|romania|🇷🇴",
  "UA": "乌克兰|ua|ukraine|🇺🇦",
  "KZ": "哈萨克|kz|kazakhstan|🇰🇿",
  "PK": "巴基斯坦|pk|pakistan|🇵🇰",
  "BD": "孟加拉|bd|bangladesh|🇧🇩",
  "EG": "埃及|eg|egypt|🇪🇬",
  "NG": "尼日利亚|ng|nigeria|🇳🇬",
  "KE": "肯尼亚|ke|kenya|🇰🇪",
  "SA": "沙特|sa|saudi|🇸🇦",
  "MO": "澳门|mo|macau|macao|🇲🇴"
}'

# ==============================================================================
# [ Utility Functions ]
# ==============================================================================

_cleanup() {
    local rc=$?
    log_debug "Cleaning up updater workspace..."
    [ -n "${TMP_CONFIG}" ] && rm -f "${TMP_CONFIG}"
    [ -n "${WORK_DIR}" ] && rm -rf "${WORK_DIR}" 2>/dev/null
    return ${rc}
}

_retry() {
    local max="${1}"; shift
    local n=0
    while [ "${n}" -lt "${max}" ]; do
        "$@" && return 0
        n=$((n + 1))
        [ "${n}" -lt "${max}" ] && { log_warn "Retry ${n} of ${max}..."; sleep 1; }
    done
    return 1
}

_is_base64() {
    local file="${1}"
    local s; s=$(head -c 512 "${file}" 2>/dev/null)
    [ -z "${s}" ] && return 1
    case "${s}" in
        "https://"*|"http://"*|"ss://"*|"vmess://"*|"vless://"*|"trojan://"*|"hysteria2://"*|"tuic://"*|"{"*|"#"*) return 1 ;;
        *[!A-Za-z0-9+/=[:space:]]*) return 1 ;;
        *) return 0 ;;
    esac
}

# ==============================================================================
# [ Modular URI Parsers ]
# ==============================================================================

_parse_ss() {
    local line="${1}"
    local core="${line#ss://}"; local tag="${core#*#}"; [ "${tag}" = "${core}" ] && tag="Shadowsocks"
    local main="${core%%#*}"; local base="${main%%@*}"; local rest="${main#*@}"
    local decoded; decoded=$(echo "${base}" | base64 -d 2>/dev/null) || return 1
    local host="${rest%%:*}"; local port="${rest#*:}"; [ "${port}" = "${rest}" ] && port="443"
    printf '{"type":"shadowsocks","tag":"%s","server":"%s","server_port":%d,"method":"%s","password":"%s"}' \
        "${tag}" "${host}" "${port}" "${decoded%%:*}" "${decoded#*:}"
    return 0
}

_parse_vmess() {
    local line="${1}"
    local decoded; decoded=$(echo "${line#vmess://}" | base64 -d 2>/dev/null) || return 1
    echo "${decoded}" | "${JQ_BIN}" -c '{
        type: "vmess",
        tag: (.ps // "VMess"),
        server: .add,
        server_port: (.port | tonumber),
        uuid: .id,
        security: (.aid | if . == 0 or . == null then "auto" else "none" end),
        alter_id: (.aid | tonumber? // 0),
        transport: (if .net == "ws" then {type: "ws", path: .path, headers: {Host: .host}} else null end),
        tls: (if .tls == "tls" then {enabled: true, server_name: .host} else null end)
    } | del(..|nulls)'
    return 0
}

_parse_generic() {
    local line="${1}"
    local proto="${line%%://*}"; local tag="${line#*#}"; [ "${tag}" = "${line}" ] && tag="${proto}"
    local core="${line#*://}"; core="${core%%#*}"; local uuid="${core%%@*}"; local rest="${core#*@}"
    local hpq="${rest%%\?*}"; local host="${hpq%%:*}"; local port="${hpq#*:}"; [ "${port}" = "${hpq}" ] && port="443"
    printf '{"type":"%s","tag":"%s","server":"%s","server_port":%d,"%s":"%s"}' \
        "${proto}" "${tag}" "${host}" "${port}" "$([ "${proto}" = "hysteria2" ] && echo "password" || echo "uuid")" "${uuid}"
    return 0
}

# ==============================================================================
# [ Core Pipeline ]
# ==============================================================================

_fetch_and_decode() {
    local url="${1}" output="${2}"
    local ua="Flux/1.0 (Sing-box; Android)"

    log_info "Fetching subscription: ${url%%#*}"
    if ! _retry "${RETRY_COUNT}" curl -L -s --insecure --http1.1 --compressed --user-agent "${ua}" -o "${output}" "${url}"; then
        log_error "Download failed"; return 1
    fi

    if _is_base64 "${output}"; then
        log_debug "Decoding Base64 content..."
        base64 -d "${output}" > "${output}.tmp" && mv "${output}.tmp" "${output}" || { log_error "Decode fail"; return 1; }
    fi
    return 0
}

_parse_to_json() {
    local input="${1}" output="${2}"

    if grep -q "{" "${input}" && grep -q "outbounds" "${input}"; then
        log_debug "Detected sing-box format"; cp "${input}" "${output}"
    else
        log_debug "Parsing URI list..."
        (
            echo '{"outbounds": ['
            local first=1
            while read -r line; do
                [ -z "${line}" ] && continue
                [ "${first}" -eq 0 ] && printf ","
                local node=""
                case "${line}" in
                    ss://*) node=$(_parse_ss "${line}") ;;
                    vmess://*) node=$(_parse_vmess "${line}") ;;
                    vless://*|trojan://*|hysteria2://*|tuic://*) node=$(_parse_generic "${line}") ;;
                esac
                [ -n "${node}" ] && { echo "${node}"; first=0; }
            done < "${input}"
            echo ']}'
        ) > "${output}"
    fi

    local refined="${output}.ref"
    if ! "${JQ_BIN}" \
        --arg exclude "${EXCLUDE_REMARKS}" \
        --argjson renames "${RENAME_RULES:-[]}" \
        --arg cleanup_emoji "${PREF_CLEANUP_EMOJI}" \
        --argjson infra "${INFRASTRUCTURE_TYPES}" \
        '
        .outbounds |= map(
            select(.tag != null and (.type | IN($infra[]) | not)) |
            (if ($exclude != "") then select(.tag | test($exclude; "i") | not) else . end) |
            reduce ($renames[]? // empty) as $r (.; if $r.match then .tag |= gsub($r.match; $r.replace) else . end) |
            (if $cleanup_emoji == "1" then
                .tag |= gsub("[🇦-🇿]{2}|[🌀-🗿]|[😀-🙏]|[🚀-🛿]|[☀-⟿]|[⺀-⻿]|[\u2600-\u27BF]"; "")
             else . end) |
            .tag |= (if . then
                gsub("[$¥](?<n>[0-9.]+)([xX倍率]*)"; "\(.n)x") |
                gsub("(?<n>[0-9.]+)([xX倍率]+)"; "\(.n)x") |
                gsub("(^\\s+|\\s+$)"; "") | gsub("\\s{2,}"; " ")
             else . end) |
            .tag |= (if . == "" then .type else . end) |
            .tag |= (if (length > 32) then (.[0:29] + "...")
             else . end)
        )
        ' "${output}" > "${refined}"; then
        log_warn "Refinement failed, using raw JSON"
    else
        mv "${refined}" "${output}"
    fi
    return 0
}

_process_config() {
    local output="${1}" sub_json="${2}"
    "${JQ_BIN}" -n \
        --slurpfile sub "${sub_json}" \
        --slurpfile template "${TEMPLATE_FILE}" \
        --argjson map "${DEFAULT_COUNTRY_MAP}" \
        --argjson infra "${INFRASTRUCTURE_TYPES}" \
        '
        ($template[0]) as $tpl | ($sub[0].outbounds // []) as $nodes |
        ($nodes | map(select(.type | IN($infra[]) | not))) as $proxies |
        ([$tpl.outbounds[]? | select(.type=="selector").tag] | map(. as $t | if $map[$t] then $map[$t] else empty end) | join("|")) as $gp |
        (if ($gp != "") then ($proxies | map(select(.tag | test($gp; "i")))) else $proxies end) as $valid |
        $tpl | .outbounds |= (
            map(
                if .type == "selector" then
                    .tag as $tag |
                    if $map[$tag] then
                        .outbounds = ($valid | map(select(.tag | test($map[$tag]; "i"))) | map(.tag))
                    elif (.tag | IN("PROXY", "GLOBAL", "AUTO")) and ((.outbounds | length) == 0) then
                        .outbounds = ($valid | map(.tag))
                    else . end
                else . end
            ) + $valid
        )
        ' > "${output}"
    return 0
}

_validate_and_deploy() {
    local new_cfg="${1}" core_cfg="${2}"
    # Basic validation
    local count; count=$("${JQ_BIN}" --argjson infra "${INFRASTRUCTURE_TYPES}" \
        '[.outbounds[] | select(.type | IN($infra[]) | not)] | length' "${new_cfg}" 2>/dev/null || echo 0)
    [ "${count}" -gt 0 ] || { log_error "No proxy nodes generated"; return 1; }

    # Atomic Deploy with Single Backup
    [ -f "${core_cfg}" ] && {
        cp -p "${core_cfg}" "${core_cfg}.bak"
        log_debug "Backup created: $(basename "${core_cfg}.bak")"
    }

    mv -f "${new_cfg}" "${core_cfg}" && chmod 644 "${core_cfg}"
    log_info "Deployed: ${count} nodes"
    return 0
}

# ==============================================================================
# [ Main Orchestration ]
# ==============================================================================

do_update() {
    trap _cleanup EXIT INT TERM

    # Load config: prefer cache_config if valid, fallback to settings
    if [ -f "${CACHE_META_FILE}" ] && [ -f "${CACHE_CONFIG_FILE}" ]; then
        . "${CACHE_CONFIG_FILE}"
    elif [ -f "${SETTINGS_FILE}" ]; then
        . "${SETTINGS_FILE}"
    else
        log_error "No configuration found"
        return 1
    fi

    log_info "Starting subscription update..."

    # Setup safe workspace
    WORK_DIR=$(mktemp -d "${RUN_DIR}/work.XXXXXX") || return 1
    local sub_raw="${WORK_DIR}/sub_raw"
    local sub_json="${WORK_DIR}/sub.json"
    TMP_CONFIG="${WORK_DIR}/config.json"

    # Check dependencies
    [ -f "${JQ_BIN}" ] || { log_error "JQ missing"; return 1; }
    [ -f "${TEMPLATE_FILE}" ] || { log_error "Template missing"; return 1; }
    [ ! -x "${JQ_BIN}" ] && chmod +x "${JQ_BIN}" 2>/dev/null

    # Execution
    run "Fetch subscription" _fetch_and_decode "${SUBSCRIPTION_URL%%#*}" "${sub_raw}" || return 1
    run "Parse to JSON" _parse_to_json "${sub_raw}" "${sub_json}" || return 1
    run "Merge with template" _process_config "${TMP_CONFIG}" "${sub_json}" || return 1
    run "Final validation & Deploy" _validate_and_deploy "${TMP_CONFIG}" "${CONFIG_FILE}" || return 1

    TMP_CONFIG="" # Safety: deployed successfully
    return 0
}

main() {
    local action="${1:-update}"

    case "${action}" in
        update)
            do_update
            ;;
        *)
            echo "Usage: $0 {update}"
            exit 1
            ;;
    esac
}

main "$@"
