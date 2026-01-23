#!/system/bin/sh

# Flux Subscription Updater
# Synchronizes nodes and templates


# Environment Setup

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "$SCRIPT_DIR/const"
. "$SCRIPT_DIR/log"

LOG_COMPONENT="Updt"
TMP_CONFIG=""

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

_cleanup() {
    log_debug "Cleaning up updater artifacts..."
    [ -n "$TMP_CONFIG" ] && rm -f "$TMP_CONFIG"
    rm -f "$TMP_SUB_CONVERTED" "$GENERATE_FILE" 2>/dev/null
    return 0
}

_retry() {
    local max="$1"; shift
    local n=0
    while [ $n -lt $max ]; do
        "$@" && return 0
        n=$((n + 1))
        [ $n -lt $max ] && { log_warn "Retry $n of $max..."; sleep 1; }
    done
    return 1
}

# Update pipeline steps

_init_update() {
    [ -n "$SUBSCRIPTION_URL" ] || { log_error "No subscription"; return 1; }

    for tool in "$SUBCONVERTER_BIN" "$JQ_BIN" "$TEMPLATE_FILE" "$COUNTRY_MAP_FILE"; do
        [ ! -f "$tool" ] && { log_error "Updater tool missing: $tool"; return 1; }
    done

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
    return 0
}

_process_config() {
    local output="$1"
    
    if ! "$JQ_BIN" -n \
        --slurpfile sub "$TMP_SUB_CONVERTED" \
        --slurpfile map "$COUNTRY_MAP_FILE" \
        --slurpfile template "$TEMPLATE_FILE" \
        '($template[0]) as $template | '"$JQ_SCRIPT_ONE_PASS" > "$output"; then
        log_error "JQ processing failed"
        rm -f "$output"
        return 1
    fi
    
    if [ ! -s "$output" ]; then
        log_error "JQ processing returned empty file"
        rm -f "$output"
        return 1
    fi
    return 0
}

_validate_config() {
    local target="$1"
    local nodes_count
    nodes_count=$("$JQ_BIN" '[.outbounds[] | select(.type != "selector" and .type != "urltest" and .type != "direct" and .type != "block" and .type != "dns")] | length' "$target" 2>/dev/null || echo 0)
    [ "$nodes_count" -gt 0 ] && return 0
    return 1
}

# Main Update Orchestration

should_update() {
    [ ! -f "$CONFIG_FILE" ] && return 0
    
    local last_update
    last_update=$(stat -c%Y "$CONFIG_FILE" 2>/dev/null || stat -f%m "$CONFIG_FILE" 2>/dev/null || echo 0)
    [ "$last_update" = "0" ] && return 0
    
    local elapsed
    elapsed=$(($(date +%s) - last_update))
    [ "$elapsed" -ge "$UPDATE_INTERVAL" ] && return 0
    return 1
}

do_update() {
    # Secure temporary file
    TMP_CONFIG=$(mktemp "$RUN_DIR/config.json.XXXXXX")
    chmod 600 "$TMP_CONFIG"
    
    run "Initialize update" _init_update || return 1
    run "Convert subscription" _convert_subscription || return 1
    run "Process config" _process_config "$TMP_CONFIG" || return 1
    run "Validate config" _validate_config "$TMP_CONFIG" || return 1

    if [ -f "$CONFIG_FILE" ]; then
        run "Backup current config" cp -pf "$CONFIG_FILE" "$CONFIG_BACKUP"
    fi
    run "Deploy new config" mv -f "$TMP_CONFIG" "$CONFIG_FILE"
    chmod 644 "$CONFIG_FILE"
    
    return 0
}

# Entry point

main() {
    trap _cleanup EXIT INT TERM

    local action="${1:-}"
    local rc=0
    
    case "$action" in
        check)
            if should_update; then
                log_info "Update interval exceeded"
                do_update
                rc=$?
            else
                log_debug "Skipping update"
            fi
            ;;
        *)
            for file in "$CACHE_CONFIG_FILE" "$SETTINGS_FILE"; do
                if [ -f "$file" ]; then
                    set -a; . "$file"; set +a
                    break
                fi
            done

            log_info "Forcing update..."
            do_update
            rc=$?
            ;;
    esac
    return $rc
}

main "$@"
