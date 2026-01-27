#!/system/bin/sh

# ==============================================================================
# [ Flux Subscription Updater ]
# Description: Synchronizes nodes and templates via one-pass JQ merging logic.
# ==============================================================================

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "$SCRIPT_DIR/const"
. "$SCRIPT_DIR/log"

LOG_COMPONENT="Updt"
TMP_CONFIG=""

# ==============================================================================
# [ JQ Processing Logic ]
# ==============================================================================

# Highly optimized one-pass JQ script to merge subscription nodes into the template.
# Technical Details:
# 1. Extracts valid outbound nodes from subscription (filtering out infrastructure metadata).
# 2. Assigns consistent labels and IDs for internal routing consistency.
# 3. Merges the resulting node array into the base sing-box JSON template.

# One-pass JQ script to merge subscription nodes into the template
# 1. Extracts valid nodes from subscription (excluding infra types like dns/direct)
# 2. Maps nodes to selector groups based on country_map
# 3. Injects nodes into template outbounds
readonly JQ_SCRIPT_ONE_PASS='
    # Helper: Extract clean nodes from subscription
    (($sub[0].outbounds // []) | map(select(
        .type != "selector" and 
        .type != "urltest" and 
        .type != "direct" and 
        .type != "block" and 
        .type != "dns"
    ))) as $clean_nodes |
    
    ($template.outbounds // []) as $tpl_outbounds |
    ($map[0] // {}) as $country_map |
    
    # Pre-calculate regex pattern for all groups in country_map
    (
        [$tpl_outbounds[]? | select(.type=="selector").tag] 
        | map(. as $tag | if ($country_map[$tag]) then $country_map[$tag] else empty end)
        | join("|")
    ) as $group_pattern |
    
    # Filter nodes that match at least one group pattern
    (
        if ($group_pattern != "") then
            ($clean_nodes | map(select(.tag | test($group_pattern; "i")))) 
        else 
            $clean_nodes 
        end
    ) as $valid_nodes |

    # Update template outbounds with mapped nodes
    $template | .outbounds |= map(
        if (.type == "selector") and ($country_map[.tag] != null) then
            .tag as $group_tag |
            .outbounds = (
                $valid_nodes
                | map(select(.tag | test($country_map[$group_tag]; "i")))
                | map(.tag)
            )
        elif (.tag == "PROXY" or .tag == "GLOBAL" or .tag == "AUTO") and ((.outbounds | length) == 0) then
            .outbounds = ($valid_nodes | map(.tag))
        else
            .
        end
    ) | 
    
    # Append raw node definitions to the end
    .outbounds += $valid_nodes
'

# ==============================================================================
# [ Internal Helper Functions ]
# ==============================================================================

_cleanup() {
    log_debug "Cleaning up updater artifacts..."
    [ -n "${TMP_CONFIG:-}" ] && rm -f "$TMP_CONFIG"
    rm -f "$TMP_SUB_CONVERTED" "$GENERATE_FILE" 2>/dev/null
    return 0
}

_retry() {
    local max="$1"; shift
    local n=0
    while [ "$n" -lt "$max" ]; do
        "$@" && return 0
        n=$((n + 1))
        [ "$n" -lt "$max" ] && { log_warn "Retry $n of $max..."; sleep 1; }
    done
    return 1
}

# ==============================================================================
# [ Update Pipeline Steps ]
# ==============================================================================

_init_update() {
    [ -n "$SUBSCRIPTION_URL" ] || { log_error "No subscription URL configured"; return 1; }

    # Check and fix permissions for all required tools
    local tool
    for tool in "$SUBCONVERTER_BIN" "$JQ_BIN"; do
        [ ! -f "$tool" ] && { log_error "Tool missing: $tool"; return 1; }
        [ ! -x "$tool" ] && chmod +x "$tool" 2>/dev/null
    done

    # Verify resource files
    for res in "$TEMPLATE_FILE" "$COUNTRY_MAP_FILE"; do
        [ ! -f "$res" ] && { log_error "Resource missing: $res"; return 1; }
    done

    [ ! -d "$RUN_DIR" ] && mkdir -p "$RUN_DIR" 2>/dev/null
    
    return 0
}

_convert_subscription() {
    # Generate subconverter config dynamically
    local safe_url
    safe_url=$(printf '%s' "$SUBSCRIPTION_URL" | tr -d '\n\r ' | sed 's/[;#].*//')
    
    cat > "$GENERATE_FILE" <<EOF
[singbox_conversion]
target=singbox
url=$safe_url
path=$TMP_SUB_CONVERTED
EOF

    if ! _retry "$RETRY_COUNT" "$SUBCONVERTER_BIN" -g >/dev/null 2>&1; then
        log_error "Subconverter failed after $RETRY_COUNT retries"
        return 1
    fi

    if [ ! -s "$TMP_SUB_CONVERTED" ]; then
        log_error "Subscription conversion produced empty output"
        return 1
    fi
    return 0
}

_process_config() {
    local output="$1"
    
    if ! "$JQ_BIN" -n \
        --slurpfile sub "$TMP_SUB_CONVERTED" \
        --slurpfile map "$COUNTRY_MAP_FILE" \
        --slurpfile template "$TEMPLATE_FILE" \
        '($template[0]) as $template | '"$JQ_SCRIPT_ONE_PASS" > "$output" 2>/dev/null; then
        log_error "JQ processing failed (check JQ script syntax or input files)"
        rm -f "$output"
        return 1
    fi
    
    if [ ! -s "$output" ]; then
        log_error "JQ processing returned empty result"
        rm -f "$output"
        return 1
    fi
    return 0
}

_validate_config() {
    local target="$1"
    local nodes_count
    nodes_count=$("$JQ_BIN" '[.outbounds[] | select(.type != "selector" and .type != "urltest" and .type != "direct" and .type != "block" and .type != "dns")] | length' "$target" 2>/dev/null || echo 0)
    
    if [ "$nodes_count" -le 0 ]; then
        log_error "Validation failed: No valid proxy nodes found in generated config"
        rm -f "$target"
        return 1
    fi
    return 0
}

# ==============================================================================
# [ Main Update Orchestration ]
# ==============================================================================

should_update() {
    [ ! -f "$CONFIG_FILE" ] && return 0
    
    local last_update
    last_update=$(stat -c%Y "$CONFIG_FILE" 2>/dev/null || stat -f%m "$CONFIG_FILE" 2>/dev/null || echo 0)
    [ "$last_update" = "0" ] && return 0
    
    local elapsed=$(($(date +%s) - last_update))
    [ "$elapsed" -ge "$UPDATE_INTERVAL" ] && return 0
    return 1
}

do_update() {
    local rc=0
    TMP_CONFIG=$(mktemp "$RUN_DIR/config.json.XXXXXX")
    chmod 600 "$TMP_CONFIG"
    
    run "Initialize update" _init_update || return 1
    run "Convert subscription" _convert_subscription || return 1
    run "Merge components" _process_config "$TMP_CONFIG" || return 1
    run "Validate output" _validate_config "$TMP_CONFIG" || return 1

    if [ -f "$CONFIG_FILE" ]; then
        run "Backup current config" cp -pf "$CONFIG_FILE" "$CONFIG_BACKUP"
    fi
    
    run "Deploy new config" mv -f "$TMP_CONFIG" "$CONFIG_FILE"
    chmod 644 "$CONFIG_FILE"
    
    # Clear TMP_CONFIG variable so cleanup doesn't delete the deployed file
    TMP_CONFIG=""
    return 0
}

# ==============================================================================
# [ Execution Entry Point ]
# ==============================================================================

main() {
    trap _cleanup EXIT INT TERM

    local action="${1:-}"
    local rc=0
    
    case "$action" in
        check)
            if should_update; then
                log_info "Update interval exceeded, starting update..."
                do_update
                rc=$?
            else
                log_debug "Config is up to date, skipping"
            fi
            ;;
        *)
            # Source settings if not already provided by environment
            [ -z "${SUBSCRIPTION_URL:-}" ] && {
                for file in "$CACHE_CONFIG_FILE" "$SETTINGS_FILE"; do
                    if [ -f "$file" ]; then
                        set -a; . "$file"; set +a
                        break
                    fi
                done
            }

            log_info "Starting forced update..."
            do_update
            rc=$?
            ;;
    esac
    return $rc
}

main "$@"
