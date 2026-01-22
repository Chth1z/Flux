#!/system/bin/sh

# Flux Subscription Updater
# Synchronizes nodes and templates


# Environment Setup

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "$SCRIPT_DIR/const"
. "$SCRIPT_DIR/log"

for file in "$CACHE_CONFIG_FILE" "$SETTINGS_FILE"; do
    if [ -f "$file" ]; then
        set -a; . "$file"; set +a
        break
    fi
done

LOG_COMPONENT="Updt"

# JQ Processing Logic

readonly JQ_SCRIPT_ONE_PASS='
    ($sub[0].outbounds // []) as $sub_nodes |
    ($map[0] // {}) as $country_map |
    
    (
        [$template.outbounds[]? | select(.type=="selector").tag] 
        | map(
            . as $tag | 
            if ($country_map[$tag]) then $country_map[$tag] else empty end
          )
        | join("|")
    ) as $pattern |
    
    ($sub_nodes | map(select(
        .type != "selector" and 
        .type != "urltest" and 
        .type != "direct" and 
        .type != "block" and 
        .type != "dns"
    ))) as $clean_nodes |
    
    (
        if ($pattern != "") then
            ($clean_nodes | map(select(.tag | test($pattern; "i")))) 
        else 
            $clean_nodes 
        end
    ) as $valid_nodes |

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
    
    .outbounds += $valid_nodes
'

# Helper functions

_retry() {
    local max="$1"; shift
    local n=0
    while [ $n -le $max ]; do
        "$@" && return 0
        n=$((n + 1))
        [ $n -le $max ] && { log_warn "Retry $n of $max..."; sleep 1; }
    done
    return 1
}

# Update pipeline steps

_init_update() {
    # Check subscription
    [ -n "$SUBSCRIPTION_URL" ] || { log_error "No subscription"; return 1; }

    # Check tools
    for tool in "$SUBCONVERTER_BIN" "$JQ_BIN" "$TEMPLATE_FILE" "$COUNTRY_MAP_FILE"; do
        [ ! -f "$tool" ] && { log_error "Updater tool missing: $tool"; return 1; }
    done

    # Fix permissions (only if not executable)
    [ -f "$SUBCONVERTER_BIN" ] && [ ! -x "$SUBCONVERTER_BIN" ] && chmod +x "$SUBCONVERTER_BIN"
    [ -f "$JQ_BIN" ] && [ ! -x "$JQ_BIN" ] && chmod +x "$JQ_BIN"
    [ ! -d "$RUN_DIR" ] && mkdir -p "$RUN_DIR"
    
    return 0
}

_convert_subscription() {
    cat > "$GENERATE_FILE" <<EOF
[singbox_conversion]
target=singbox
url=$SUBSCRIPTION_URL
path=$TMP_SUB_CONVERTED
EOF
    _retry "$RETRY_COUNT" "$SUBCONVERTER_BIN" -g >/dev/null 2>&1
    if [ ! -s "$TMP_SUB_CONVERTED" ]; then
        log_error "Subscription conversion failed or returned empty"
        return 1
    fi
}

_process_config() {
    [ -f "$CONFIG_FILE" ] && cp -f "$CONFIG_FILE" "$CONFIG_BACKUP" 2>/dev/null
    
    "$JQ_BIN" -n \
        --slurpfile sub "$TMP_SUB_CONVERTED" \
        --slurpfile map "$COUNTRY_MAP_FILE" \
        --slurpfile template "$TEMPLATE_FILE" \
        '($template[0]) as $template | '"$JQ_SCRIPT_ONE_PASS" > "$CONFIG_FILE"
    
    if [ $? -ne 0 ] || [ ! -s "$CONFIG_FILE" ]; then
        log_error "Config merger failed"
        [ -f "$CONFIG_BACKUP" ] && mv -f "$CONFIG_BACKUP" "$CONFIG_FILE"
        return 1
    fi
}

_validate_config() {
    local nodes_count
    nodes_count=$("$JQ_BIN" '[.outbounds[] | select(.type != "selector" and .type != "urltest" and .type != "direct" and .type != "block" and .type != "dns")] | length' "$CONFIG_FILE" 2>/dev/null || echo 0)
    [ "$nodes_count" -gt 0 ]
}

# Main Update Orchestration

should_update() {
    [ ! -f "$CONFIG_FILE" ] && return 0
    
    local last_update
    last_update=$(stat -c%Y "$CONFIG_FILE" 2>/dev/null || stat -f%m "$CONFIG_FILE" 2>/dev/null || echo 0)
    [ "$last_update" -eq 0 ] && return 0
    
    local elapsed
    elapsed=$(($(date +%s) - last_update))
    [ "$elapsed" -ge "$UPDATE_INTERVAL" ]
}

do_update() {
    run "Initialize update" _init_update || return 1
    run "Convert subscription" _convert_subscription || return 1
    run "Process config" _process_config || return 1
    run "Validate config" _validate_config || return 1
}

# Entry point

main() {
    trap 'rm -f "$TMP_SUB_CONVERTED" "$GENERATE_FILE" 2>/dev/null' EXIT

    local action="${1:-}"
    
    case "$action" in
        check)
            should_update && { log_info "Update interval exceeded"; do_update; } || log_debug "Skipping update"
            ;;
        *)
            log_info "Forcing update..."
            do_update
            ;;
    esac
}

main "$@"
