#!/system/bin/sh

# ==============================================================================
# Flux Subscription Updater (updater.sh)
# ==============================================================================

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "$SCRIPT_DIR/const"
. "$SCRIPT_DIR/log"
. "$SCRIPT_DIR/config"

LOG_COMPONENT="Update"

# ==============================================================================
# [ Helpers ]
# ==============================================================================

_COUNTRY_MAP_CACHE=""

_load_country_map() {
    [ -z "$_COUNTRY_MAP_CACHE" ] && _COUNTRY_MAP_CACHE=$(cat "$COUNTRY_MAP_FILE" 2>/dev/null || echo "{}")
    echo "$_COUNTRY_MAP_CACHE"
}

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

_cleanup() {
    rm -f "$TMP_SUB_CONVERTED" "$TMP_NODES_EXTRACTED" "$GENERATE_FILE" 2>/dev/null
}

# ==============================================================================
# [ Pipeline Steps ]
# ==============================================================================

_init_update() {
    # Check subscription
    [ -n "$SUBSCRIPTION_URL" ] || { prop_error "No subscription"; return 1; }

    # Check tools
    [ -f "$SUBCONVERTER_BIN" ] && [ -f "$JQ_BIN" ] && [ -f "$TEMPLATE_FILE" ] || return 1

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
    _retry "$RETRY_COUNT" "$SUBCONVERTER_BIN" -g >/dev/null 2>&1 && [ -s "$TMP_SUB_CONVERTED" ]
}

_filter_proxies() {
    local country_map filter_regex
    country_map=$(_load_country_map)
    filter_regex=$("$JQ_BIN" -r --argjson map "$country_map" "$JQ_SCRIPT_BUILD_REGEX" "$TEMPLATE_FILE")
    
    "$JQ_BIN" --arg pattern "$filter_regex" "$JQ_SCRIPT_EXTRACT_NODES" "$TMP_SUB_CONVERTED" > "$TMP_NODES_EXTRACTED"
    
    [ -s "$TMP_NODES_EXTRACTED" ] && [ "$("$JQ_BIN" 'length' "$TMP_NODES_EXTRACTED" 2>/dev/null)" -gt 0 ]
}

_merge_config() {
    [ -f "$CONFIG_FILE" ] && cp -f "$CONFIG_FILE" "$CONFIG_BACKUP" 2>/dev/null
    
    local country_map
    country_map=$(_load_country_map)
    
    "$JQ_BIN" --slurpfile nodes "$TMP_NODES_EXTRACTED" \
         --argjson country_map "$country_map" \
         "$JQ_SCRIPT_MERGE_CONFIG" \
         "$TEMPLATE_FILE" > "$CONFIG_FILE"
    
    if [ $? -ne 0 ] || [ ! -s "$CONFIG_FILE" ]; then
        [ -f "$CONFIG_BACKUP" ] && mv -f "$CONFIG_BACKUP" "$CONFIG_FILE"
        return 1
    fi
}

_validate_config() {
    local nodes_count
    nodes_count=$("$JQ_BIN" '[.outbounds[] | select(.type != "selector" and .type != "urltest" and .type != "direct" and .type != "block" and .type != "dns")] | length' "$CONFIG_FILE" 2>/dev/null || echo 0)
    [ "$nodes_count" -gt 0 ]
}

# ==============================================================================
# [ Update Logic ]
# ==============================================================================

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
    run "Filter proxies" _filter_proxies || return 1
    run "Merge config" _merge_config || return 1
    run "Validate config" _validate_config || return 1
}

# ==============================================================================
# [ Entry Point ]
# ==============================================================================

main() {
    trap _cleanup EXIT
    load_flux_config
    
    case "${1:-update}" in
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
