#!/system/bin/sh

# ==============================================================================
# [ Flux Subscription Updater ]
# Description: Industrial-grade node synchronization with atomic deployment.
# ==============================================================================

# Strict error handling
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

readonly SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

. "${SCRIPT_DIR}/lib"
. "${SCRIPT_DIR}/log"

readonly LOG_COMPONENT="Updt"

load_config || exit 1

# State management
TMP_CONFIG=""
WORK_DIR=""

# ==============================================================================
# [ Core Pipeline ]
# ==============================================================================

_fetch_and_decode() {
    local url="${1}"
    local output="${2}"
    local ua="Flux/1.0 (Sing-box; Android)"

    log_info "Fetching subscription: ${url%%#*}"
    # Use pipe to avoid temp file for base64 decode if possible, but curl output needs to be checked.
    # Current implementation downloads to file first.
    if ! retry "${RETRY_COUNT}" curl -L -f -s --http1.1 --compressed \
        --connect-timeout "${UPDATE_TIMEOUT}" --max-time "${UPDATE_TIMEOUT}" \
        --user-agent "${ua}" -o "${output}" "${url}"; then
        log_error "Download failed (check URL or connection)"
        return 1
    fi

    if is_base64 "${output}"; then
        log_debug "Decoding Base64 content..."
        # Decode in-place
        base64 -d "${output}" >"${output}.tmp" && mv "${output}.tmp" "${output}" || {
            log_error "Decode fail"
            return 1
        }
    fi
    return 0
}

readonly UPDATER_COUNTRY_MAP='{
    "HK": "香港|港|hk|hongkong|hong kong",
    "TW": "台湾|台|tw|taiwan",
    "JP": "日本|日|jp|japan",
    "SG": "新加坡|新|sg|singapore",
    "US": "美国|美|us|usa|united states|america",
    "KR": "韩国|韩|kr|korea|south korea",
    "UK": "英国|英|uk|gb|united kingdom|britain",
    "DE": "德国|德|de|germany",
    "FR": "法国|法|fr|france",
    "CA": "加拿大|加|ca|canada",
    "AU": "澳大利亚|澳洲|澳|au|australia",
    "RU": "俄罗斯|俄|ru|russia",
    "NL": "荷兰|荷|nl|netherlands",
    "IN": "印度|印|in|india",
    "TR": "土耳其|土|tr|turkey|turkiye",
    "IT": "意大利|意|it|italy",
    "CH": "瑞士|ch|switzerland",
    "SE": "瑞典|se|sweden",
    "BR": "巴西|br|brazil",
    "AR": "阿根廷|ar|argentina",
    "VN": "越南|vn|vietnam",
    "TH": "泰国|th|thailand",
    "PH": "菲律宾|菲|ph|philippines",
    "MY": "马来西亚|马来|my|malaysia",
    "ID": "印尼|印度尼西亚|id|indonesia",
    "ES": "西班牙|西|es|spain",
    "PL": "波兰|pl|poland",
    "FI": "芬兰|fi|finland",
    "NO": "挪威|no|norway",
    "DK": "丹麦|dk|denmark"
}'

readonly INFRASTRUCTURE_TYPES='["selector","urltest","direct","block","dns"]'

_transform_nodes() {
    local input="${1}"
    local output="${2}"

    run_pipeline() {
        # shellcheck disable=SC2016
        "${JQ_BIN}" -n \
            --slurpfile template "${TEMPLATE_FILE}" \
            --arg exclude "${UPDATER_EXCLUDE_REMARKS}" \
            --argjson renames "${UPDATER_RENAME_RULES}" \
            --argjson map "${UPDATER_COUNTRY_MAP}" \
            --argjson infra "${INFRASTRUCTURE_TYPES}" \
            --argjson maxlen "${UPDATER_MAX_TAG_LENGTH}" \
            --arg cleanup_emoji "${PREF_CLEANUP_EMOJI}" \
            '
            ($template[0]) as $tpl |
            [inputs | (.outbounds? // .)] | flatten as $raw_nodes |

            # --- Phase A: Node Refinement ---
            (
                $raw_nodes | map(
                    select(.tag != null and (.type | IN($infra[]) | not)) |
                    (if ($exclude != "") then select(.tag | test($exclude; "i") | not) else . end) |
                    reduce ($renames[]? // empty) as $r (.; if $r.match then .tag |= gsub($r.match; $r.replace) else . end) |
                    (if $cleanup_emoji == "1" then .tag |= gsub("[🇦-🇿]{2}|[🌀-🗿]|[😀-🙏]|[🚀-🛿]|[☀-⟿]|[⺀-⻿]|[\u2600-\u27BF]"; "") else . end) |
                    .tag |= (if . then gsub("[$¥](?<n>[0-9.]+)([xX倍率]*)"; "\(.n)x") | gsub("(?<n>[0-9.]+)([xX倍率]+)"; "\(.n)x") | gsub("(^\\s+|\\s+$)"; "") | gsub("\\s{2,}"; " ") else . end) |
                    .tag |= (if . == "" then .type else . end) |
                    .tag |= (if (length > $maxlen) then (.[0:($maxlen - 3)] + "...") else . end)
                )
            ) as $refined_proxies |

            # --- Phase B: Categorization & Grouping (Dynamic) ---
            (
                ($map | to_entries) as $m |
                $refined_proxies | reduce .[] as $p ({};
                    reduce $m[] as $item (.;
                        if ($p.tag | test($item.value; "i")) then
                            .[$item.key] += [$p.tag]
                        else . end
                    )
                )
            ) as $groups |

            # --- Phase C: Final Assembly ---
            $tpl | .outbounds |= (
                map(
                    if (.type == "selector" and (.outbounds | length) == 0) then
                        if $groups[.tag] then
                            .outbounds = $groups[.tag]
                        elif (.tag | IN("PROXY", "GLOBAL", "AUTO")) then
                            .outbounds = ($refined_proxies | map(.tag))
                        else . end
                    else . end
                ) + $refined_proxies
            ) | del(..|nulls)
            ' >"${output}"
    }

    log_debug "Executing unified processing pipeline..."
    if "${JQ_BIN}" -e '.outbounds? | type == "array"' "${input}" >/dev/null 2>&1; then
        log_debug "Detected sing-box format"
        cat "${input}" | run_pipeline || {
            log_error "Pipeline execution failed"
            return 1
        }
    else
        log_debug "Parsing URI list (Fast Mode)..."

        # Use awk to parse URIs in bulk -> jq aggregation -> jq pipeline
        awk '
# Parses URIs into sing-box compatible JSON objects
# Supports: vmess, vless, trojan, hysteria, hysteria2, tuic, socks, http, snell, ss

BEGIN {
    # Base64 Table
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for (i = 0; i < 64; i++) b64_val[substr(b64, i+1, 1)] = i
    b64_val["-"] = 62; b64_val["_"] = 63
}

function decode_base64(str,    len, i, bits, val, out, c) {
    len = length(str)
    bits = 0
    val = 0
    out = ""
    for (i = 1; i <= len; i++) {
        c = substr(str, i, 1)
        if (c == "=") break
        if (c in b64_val) {
            val = val * 64 + b64_val[c]
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out = out sprintf("%c", int(val / (2^bits)) % 256)
            }
        }
    }
    return out
}

function json_escape(str) {
    gsub(/\\/, "\\\\", str)
    gsub(/"/, "\\\"", str)
    gsub(/\n/, "\\n", str)
    gsub(/\r/, "\\r", str)
    gsub(/\t/, "\\t", str)
    return str
}

function get_json_val(json, key,   pat, start, end, val) {
    pat = "\"" key "\"[[:space:]]*:[[:space:]]*"
    start = match(json, pat)
    if (start == 0) return ""
    
    rest = substr(json, start + RLENGTH)
    
    if (substr(rest, 1, 1) == "\"") {
        end = index(substr(rest, 2), "\"")
        if (end == 0) return ""
        val = substr(rest, 2, end - 1)
        return val
    } else {
        match(rest, /^[^,}\]]+/)
        val = substr(rest, 1, RLENGTH)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        return val
    }
}

function url_decode(str,   res, i, c, hex, h) {
    res = ""
    for (i = 1; i <= length(str); i++) {
        c = substr(str, i, 1)
        if (c == "+") {
            res = res " "
        } else if (c == "%") {
            hex = toupper(substr(str, i + 1, 2))
            if (length(hex) == 2 && index("0123456789ABCDEF", substr(hex, 1, 1)) && index("0123456789ABCDEF", substr(hex, 2, 1))) {
                h = index("0123456789ABCDEF", substr(hex, 1, 1)) - 1
                h = h * 16 + index("0123456789ABCDEF", substr(hex, 2, 1)) - 1
                res = res sprintf("%c", h)
                i += 2
            } else {
                res = res c
            }
        } else {
            res = res c
        }
    }
    return res
}

{
    uri = $0
    if (uri == "" || uri ~ /^#/) next
    
    idx = index(uri, "://")
    if (idx == 0) next
    proto = substr(uri, 1, idx - 1)
    body = substr(uri, idx + 3)
    
    tag = ""
    server = ""
    port = 0
    
    # --- VMESS ---
    if (proto == "vmess") {
        json_str = decode_base64(body)
        
        ps = get_json_val(json_str, "ps")
        add = get_json_val(json_str, "add")
        port = get_json_val(json_str, "port") + 0
        id = get_json_val(json_str, "id")
        aid = get_json_val(json_str, "aid")
        scy = get_json_val(json_str, "scy")
        net = get_json_val(json_str, "net")
        host = get_json_val(json_str, "host")
        path = get_json_val(json_str, "path")
        tls = get_json_val(json_str, "tls")
        sni = get_json_val(json_str, "sni")
        
        if (add == "") next

        printf "{\"type\":\"vmess\",\"tag\":\"%s\",\"server\":\"%s\",\"server_port\":%d,\"uuid\":\"%s\"", \
            json_escape(ps != "" ? ps : "VMess"), json_escape(add), port, json_escape(id)
            
        if (aid != "" && aid != "0") printf ",\"alter_id\":%d", aid
        if (scy == "auto" || scy == "") printf ",\"security\":\"auto\""
        else printf ",\"security\":\"%s\"", scy
        
        if (net == "ws") {
            printf ",\"transport\":{\"type\":\"ws\",\"path\":\"%s\",\"headers\":{\"Host\":\"%s\"}}", \
                json_escape(path), json_escape(host)
        }
        
        if (tls == "tls") {
            printf ",\"tls\":{\"enabled\":true,\"server_name\":\"%s\"}", json_escape(sni != "" ? sni : host)
        }
        
        print "}"
        next
    }
    
    # --- SS ---
    if (proto == "ss") {
        tag_idx = index(body, "#")
        if (tag_idx > 0) {
            tag = substr(body, tag_idx + 1)
            body = substr(body, 1, tag_idx - 1)
        } else {
            tag = "shadowsocks"
        }
        
        at_idx = index(body, "@")
        if (at_idx > 0) {
            userinfo = substr(body, 1, at_idx - 1)
            hostport = substr(body, at_idx + 1)
            if (index(userinfo, ":") == 0) userinfo = decode_base64(userinfo)
        } else {
            decoded = decode_base64(body)
            at_idx = index(decoded, "@")
            if (at_idx > 0) {
                userinfo = substr(decoded, 1, at_idx - 1)
                hostport = substr(decoded, at_idx + 1)
            } else {
                next
            }
        }
        
        split(userinfo, up, ":")
        method = up[1]
        password = up[2]
        
        colon_idx = index(hostport, ":")
        host = substr(hostport, 1, colon_idx - 1)
        port = substr(hostport, colon_idx + 1) + 0
        
        printf "{\"type\":\"shadowsocks\",\"tag\":\"%s\",\"server\":\"%s\",\"server_port\":%d,\"method\":\"%s\",\"password\":\"%s\"}\n", \
            json_escape(tag), json_escape(host), port, json_escape(method), json_escape(password)
        next
    }
    
    # --- Generic ---
    tag_idx = index(body, "#")
    if (tag_idx > 0) {
        tag = substr(body, tag_idx + 1)
        body = substr(body, 1, tag_idx - 1)
        tag = url_decode(tag)
    } else {
        tag = proto
    }
    
    at_idx = index(body, "@")
    if (at_idx > 0) {
        uuid = substr(body, 1, at_idx - 1)
        hostport_path = substr(body, at_idx + 1)
    } else {
        next
    }
    
    q_idx = index(hostport_path, "?")
    if (q_idx > 0) {
        hostport = substr(hostport_path, 1, q_idx - 1)
    } else {
        hostport = hostport_path
    }
    
    # Host Port
    if (index(hostport, "[") == 1) {
        cb = index(hostport, "]")
        host = substr(hostport, 2, cb - 2)
        port_str = substr(hostport, cb + 2)
        sub(/^:/, "", port_str)
        port = port_str + 0
    } else {
        n = split(hostport, hp, ":")
        if (n >= 2) {
            port = hp[n] + 0
            host = substr(hostport, 1, length(hostport) - length(hp[n]) - 1)
        } else {
            host = hostport
            port = 443
        }
    }
    if (port == 0) port = 443

    printf "{\"type\":\"%s\",\"tag\":\"%s\",\"server\":\"%s\",\"server_port\":%d", proto, json_escape(tag), json_escape(host), port
    
    if (proto == "vless" || proto == "tuic") {
        printf ",\"uuid\":\"%s\"", json_escape(uuid)
    } else if (proto == "trojan" || proto == "hysteria2") {
        printf ",\"password\":\"%s\"", json_escape(uuid)
    } else if (proto == "hysteria") {
        printf ",\"auth\":\"%s\"", json_escape(uuid)
    } else if (proto == "socks" || proto == "http") {
         printf ",\"username\":\"%s\"", json_escape(uuid)
    } else if (proto == "snell") {
         printf ",\"psk\":\"%s\"", json_escape(uuid)
    }
    
    print "}"
}
' "${input}" | run_pipeline || {
            log_error "Pipeline execution failed"
            return 1
        }
    fi
    return 0
}

_validate_and_deploy() {
    local new_cfg="${1}"
    local core_cfg="${2}"

    # Basic validation
    local count
    count=$("${JQ_BIN}" --argjson infra "${INFRASTRUCTURE_TYPES}" \
        '[.outbounds[] | select(.type | IN($infra[]) | not)] | length' "${new_cfg}" 2>/dev/null || echo 0)

    is_int "${count}" || count=0
    [ "${count}" -gt 0 ] || {
        log_error "No proxy nodes generated"
        return 1
    }

    if [ -f "${core_cfg}" ] && cmp -s "${new_cfg}" "${core_cfg}"; then
        log_warn "Config unchanged, skip deploy"
        rm -f "${new_cfg}"
        return 0
    fi

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
    trap 'cleanup "Cleaning up updater workspace..." "${TMP_CONFIG}" "${WORK_DIR}"' EXIT INT TERM

    log_info "Starting subscription update..."

    # Setup safe workspace
    WORK_DIR=$(mktemp -d "${RUN_DIR}/work.XXXXXX") || return 1
    local sub_raw="${WORK_DIR}/sub_raw"
    TMP_CONFIG="${WORK_DIR}/config.json"

    [ -n "${SUBSCRIPTION_URL}" ] || {
        log_error "SUBSCRIPTION_URL is empty"
        return 1
    }

    # Check dependencies
    [ -f "${JQ_BIN}" ] || {
        log_error "JQ missing"
        return 1
    }
    [ -f "${TEMPLATE_FILE}" ] || {
        log_error "Template missing"
        return 1
    }
    [ ! -x "${JQ_BIN}" ] && chmod +x "${JQ_BIN}" 2>/dev/null

    # Execution stages: fetch -> transform -> deploy
    run -v "Fetch subscription" _fetch_and_decode "${SUBSCRIPTION_URL%%#*}" "${sub_raw}" || return $?
    run -v "Transform nodes" _transform_nodes "${sub_raw}" "${TMP_CONFIG}" || return $?
    run -v "Final validation & Deploy" _validate_and_deploy "${TMP_CONFIG}" "${CONFIG_FILE}" || return $?

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
