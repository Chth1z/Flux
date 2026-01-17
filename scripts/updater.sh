#!/system/bin/sh

# ==============================================================================
# Flux Subscription Updater (updater.sh)
# Description: Updates subscription, processes config templates, and updates IP lists
# ==============================================================================

# ==============================================================================
# [ Environment Setup ]
# ==============================================================================

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
. "$SCRIPT_DIR/flux.utils"
. "$SCRIPT_DIR/flux.data"

export LOG_COMPONENT="Update"

# ==============================================================================
# [ Country Mapping ]
# ==============================================================================

# Load country mapping from external JSON file (path defined in flux.utils)
# Uses: $COUNTRY_MAP_FILE

# Cache for country map (loaded once, reused)
_COUNTRY_MAP_CACHE=""

# Load country regex map from file with caching
_load_country_map() {
    if [ -z "$_COUNTRY_MAP_CACHE" ]; then
        if [ -f "$COUNTRY_MAP_FILE" ]; then
            _COUNTRY_MAP_CACHE=$(cat "$COUNTRY_MAP_FILE")
        else
            _COUNTRY_MAP_CACHE="{}"
        fi
    fi
    echo "$_COUNTRY_MAP_CACHE"
}

# ==============================================================================
# [ JQ Scripts ]
# ==============================================================================

# 1. Build Filter Regex
readonly JQ_SCRIPT_BUILD_REGEX='
    [ (.outbounds[]? | select(.type=="selector").tag) ] as $template_tags |
    ($map | to_entries | map(select(.key as $country_code | $template_tags | index($country_code))) | map(.value))
    | join("|")
'

# 2. Extract Nodes
readonly JQ_SCRIPT_EXTRACT_NODES='
    (.outbounds // []) |
    map(select(
        .type != "selector" and
        .type != "urltest" and
        .type != "direct" and
        .type != "block" and
        .type != "dns"
    )) |
    map(del(.network)) as $clean_nodes |
    
    if ($pattern | length) > 0 then
        ($clean_nodes | map(select(.tag | test($pattern; "i")))) as $filtered |
        if ($filtered | length) > 0 then $filtered else $clean_nodes end
    else
        $clean_nodes
    end
'

# 3. Generate Config (uses $country_map passed via --argjson)
readonly JQ_SCRIPT_MERGE_CONFIG='
    ($nodes[0] // []) as $valid_nodes |
    
    (.outbounds // []) |= map(
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


# ==============================================================================
# [ Utility Helpers ]
# ==============================================================================

# Retry a command with configurable attempts
# Usage: _retry <max_retries> <command...>
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

# Check if file is stale (older than N days)
# Usage: _is_file_stale <file> [days=7]
_is_file_stale() {
    local file="$1" days="${2:-7}"
    [ ! -f "$file" ] && return 0
    local now mtime
    now=$(date +%s)
    mtime=$(stat -c %Y "$file" 2>/dev/null || echo 0)
    [ $((now - mtime)) -gt $((days * 86400)) ]
}


# ==============================================================================
# [ CN IP List Management ]
# ==============================================================================

# Internal helper: download file with HTTP status validation
_download_with_validation() {
    local url="$1"
    local output="$2"
    local description="$3"
    
    local http_code
    http_code=$(curl -fsSL --connect-timeout "$UPDATE_TIMEOUT" --retry "$RETRY_COUNT" \
        -w "%{http_code}" \
        -o "$output.tmp" \
        "$url" 2>/dev/null)
    
    # Validate HTTP response code (2xx = success)
    case "$http_code" in
        2[0-9][0-9])
            if [ -s "$output.tmp" ]; then
                mv "$output.tmp" "$output"
                log_info "$description updated (HTTP $http_code)"
                return 0
            else
                log_warn "$description download empty (HTTP $http_code)"
                rm -f "$output.tmp"
                return 1
            fi
            ;;
        *)
            log_warn "$description download failed (HTTP $http_code)"
            rm -f "$output.tmp"
            return 1
            ;;
    esac
}

# Download China IP lists if bypass is enabled and file is outdated
# Uses parallel downloads for IPv4 and IPv6 when both are needed
download_cn_ip_list() {
    if [ "$BYPASS_CN_IP" -ne 1 ]; then
        log_debug "CN IP bypass disabled, skipping download"
        return 0
    fi

    log_info "Updating CN IP list..."
    
    local ipv4_needed=0
    local ipv6_needed=0
    
    # Check if updates are needed (files missing or older than 7 days)
    _is_file_stale "$CN_IP_FILE" 7 && ipv4_needed=1
    
    if [ "$PROXY_IPV6" -eq 1 ]; then
        _is_file_stale "$CN_IPV6_FILE" 7 && ipv6_needed=1
    fi
    
    # Parallel download if both needed
    if [ "$ipv4_needed" -eq 1 ] && [ "$ipv6_needed" -eq 1 ]; then
        log_debug "Fetching CN IPv4 and IPv6 lists in parallel..."
        
        _download_with_validation "$CN_IP_URL" "$CN_IP_FILE" "CN IPv4 list" &
        local pid_v4=$!
        
        _download_with_validation "$CN_IPV6_URL" "$CN_IPV6_FILE" "CN IPv6 list" &
        local pid_v6=$!
        
        wait $pid_v4 || prop_warn "CN IPv4 download failed"
        wait $pid_v6 || prop_warn "CN IPv6 download failed"
        
    elif [ "$ipv4_needed" -eq 1 ]; then
        log_debug "Fetching CN IPv4 list..."
        _download_with_validation "$CN_IP_URL" "$CN_IP_FILE" "CN IPv4 list" || \
            prop_warn "CN IPv4 download failed"
            
    elif [ "$ipv6_needed" -eq 1 ]; then
        log_debug "Fetching CN IPv6 list..."
        _download_with_validation "$CN_IPV6_URL" "$CN_IPV6_FILE" "CN IPv6 list" || \
            prop_warn "CN IPv6 download failed"
    else
        log_debug "CN IP lists are up to date"
    fi
    
    return 0
}



# ==============================================================================
# [ Cleanup & Utilities ]
# ==============================================================================

# Remove temporary files
cleanup_temp_files() {
    rm -f "$TMP_SUB_CONVERTED" "$TMP_NODES_EXTRACTED" "$GENERATE_FILE" 2>/dev/null
    log_debug "Temporary files cleaned up"
}


# ==============================================================================
# [ Validation Functions ]
# ==============================================================================

# Validate required executables and directories
validate_environment() {
    log_info "Validating environment..."
    
    [ ! -d "$TOOLS_DIR" ] && fatal "Tools directory not found: $TOOLS_DIR"
    
    cd "$TOOLS_DIR" || fatal "Cannot change to directory: $TOOLS_DIR"
    
    [ ! -x "./subconverter" ] && [ ! -f "./subconverter" ] && fatal "subconverter not found"
    [ ! -x "./jq" ] && [ ! -f "./jq" ] && fatal "jq not found"
    [ ! -f "$TEMPLATE_FILE" ] && fatal "Template missing"
    
    # Ensure executables have correct permissions
    chmod +x "./subconverter" "./jq" 2>/dev/null || true
    
    # Create run directory if missing
    [ ! -d "$RUN_DIR" ] && mkdir -p "$RUN_DIR"
    
    log_info "Environment validation passed"
}

# Exit with error message and perform cleanup
# Exit with error message and perform cleanup
fatal() {
    cleanup_temp_files
    log_error "$1"
    prop_error "$1"
    exit 1
}

# Check if a file exists and is not empty
validate_file() { [ -s "$1" ]; }


# ==============================================================================
# [ Conversion Phase ]
# ==============================================================================

# Convert subscription content to sing-box format using subconverter
download_and_convert_subscription() {
    log_info "Download and converting subscription to sing-box format..."
    
    if [ -z "$SUBSCRIPTION_URL" ]; then
        prop_error "No subscription"
        fatal "SUBSCRIPTION_URL not set"
    fi
    
    # Create configuration file for subconverter
    cat > "$GENERATE_FILE" <<EOF
[singbox_conversion]
target=singbox
url=$SUBSCRIPTION_URL
path=$TMP_SUB_CONVERTED
EOF
    
    if ! _retry "$RETRY_COUNT" ./subconverter -g >/dev/null 2>&1; then
        rm -f "$GENERATE_FILE"
        fatal "Subscription convert failed"
    fi
    
    # Validate conversion result
    if ! validate_file "$TMP_SUB_CONVERTED" "converted JSON"; then
        rm -f "$GENERATE_FILE"
        fatal "Conversion produced empty or invalid output"
    fi
    
    log_info "Conversion successful"
    
    rm -f "$GENERATE_FILE"
}


# ==============================================================================
# [ Node Processing Phase ]
# ==============================================================================

# Build dynamic filter regex based on available template groups
build_filter_regex() {
    local country_map
    country_map=$(_load_country_map)
    ./jq -r --argjson map "$country_map" \
        "$JQ_SCRIPT_BUILD_REGEX" \
        "$TEMPLATE_FILE"
}

# Extract relevant nodes and apply filtering
filter_and_extract_proxies() {
    log_info "Extracting and filtering nodes..."
    
    local filter_regex
    filter_regex=$(build_filter_regex)
    
    if [ -z "$filter_regex" ]; then
        log_info "No country groups detected, retaining all nodes"
    else
        log_info "Applying filter rules: $filter_regex"
    fi
    
    ./jq --arg pattern "$filter_regex" \
        "$JQ_SCRIPT_EXTRACT_NODES" \
        "$TMP_SUB_CONVERTED" > "$TMP_NODES_EXTRACTED"
    
    if ! validate_file "$TMP_NODES_EXTRACTED" "nodes"; then
        fatal "Node extraction produced empty result"
    fi
    
    local count
    count=$(./jq 'length' "$TMP_NODES_EXTRACTED" 2>/dev/null || echo 0)
    [ "$count" -eq 0 ] && fatal "No valid nodes extracted"
    
    log_info "Successfully extracted and filtered nodes: $count"
}


# ==============================================================================
# [ Configuration Generation Phase ]
# ==============================================================================

# Merge extracted nodes into the template to create final config
merge_nodes_into_template() {
    log_info "Generating final configuration..."
    
    [ -f "$CONFIG_FILE" ] && cp -f "$CONFIG_FILE" "$CONFIG_BACKUP" 2>/dev/null
    
    local country_map
    country_map=$(_load_country_map)
    
    ./jq --slurpfile nodes "$TMP_NODES_EXTRACTED" \
         --argjson country_map "$country_map" \
         "$JQ_SCRIPT_MERGE_CONFIG" \
         "$TEMPLATE_FILE" > "$CONFIG_FILE"
    
    if [ $? -ne 0 ] || ! validate_file "$CONFIG_FILE" "final config"; then
        if [ -f "$CONFIG_BACKUP" ]; then
            log_warn "Restoring backup configuration..."
            mv -f "$CONFIG_BACKUP" "$CONFIG_FILE"
        fi
        fatal "Configuration generation failed"
    fi
}


# ==============================================================================
# [ Final Verification ]
# ==============================================================================

# Verify the final JSON file is valid and contains nodes
validate_and_report() {
    log_info "Validating configuration..."
    
    local size nodes_count
    size=$(wc -c < "$CONFIG_FILE" 2>/dev/null || echo 0)
    
    [ "$size" -eq 0 ] && fatal "Generated configuration is empty"
    
    # Count nodes in final configuration
    nodes_count=$(./jq '
        [.outbounds[] |
            select(
                .type != "selector" and
                .type != "urltest" and
                .type != "direct" and
                .type != "block" and
                .type != "dns"
            )
        ] | length
    ' "$CONFIG_FILE" 2>/dev/null || echo 0)
    
    [ "$nodes_count" -eq 0 ] && fatal "No nodes found in final configuration"
}


# ==============================================================================
# [ Update Interval Check ]
# ==============================================================================

# Check if enough time has passed since last update
should_update() {
    local last_update current_time elapsed
    
    # Read last_update from unified state file
    last_update=$(_state_get "last_update")
    [ -z "$last_update" ] && return 0  # No timestamp = should update
    
    current_time=$(date +%s)
    elapsed=$((current_time - last_update))
    
    if [ "$elapsed" -ge "$UPDATE_INTERVAL" ]; then
        log_debug "Update interval exceeded (${elapsed}s >= ${UPDATE_INTERVAL}s)"
        return 0
    else
        local remaining=$((UPDATE_INTERVAL - elapsed))
        log_debug "Update not needed yet (${remaining}s remaining)"
        return 1
    fi
}


# ==============================================================================
# [ Update Execution ]
# ==============================================================================

# Execute the full update pipeline
do_update() {
    log_info "Starting configuration update..."
    
    # Ensure cleanup on exit
    trap cleanup_temp_files EXIT
    
    # Execute update pipeline
    validate_environment

    download_and_convert_subscription
    filter_and_extract_proxies
    merge_nodes_into_template
    validate_and_report
    
    # Download CN IP list if enabled in config
    download_cn_ip_list
    
    # Update timestamp in unified state file
    _state_set "last_update" "$(date +%s)"
    
    # Cleanup
    cleanup_temp_files
    
    log_info "Update completed"
}


# ==============================================================================
# [ Entry Point ]
# ==============================================================================

main() {
    load_flux_config
    
    local action="${1:-update}"
    
    case "$action" in
        check)
            # Called by start.sh - only update if interval exceeded
            if should_update; then
                log_info "Update interval exceeded, starting update..."
                do_update
            else
                log_debug "Skipping update (interval not reached)"
            fi
            ;;
        update|*)
            # Direct execution - force immediate update
            log_info "Forcing immediate update..."
            do_update
            ;;
    esac
    
    exit 0
}

main "$@"