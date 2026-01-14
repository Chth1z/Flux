#!/system/bin/sh

# ==============================================================================
# FLUX Installer (customize.sh)
# Description: Advanced Magisk/KernelSU/APatch installer script
# ==============================================================================

SKIPUNZIP=1

# ==============================================================================
# [ Environment Check ]
# ==============================================================================

if [ "$BOOTMODE" != true ]; then
    ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ui_print "! Please install in Magisk/KernelSU/APatch Manager"
    ui_print "! Install from Recovery is NOT supported"
    abort "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

# ==============================================================================
# [ Constants & Paths ]
# ==============================================================================

readonly FLUX_DIR="/data/adb/flux"
readonly CONF_DIR="$FLUX_DIR/conf"
readonly BIN_DIR="$FLUX_DIR/bin"
readonly SCRIPTS_DIR="$FLUX_DIR/scripts"
readonly RUN_DIR="$FLUX_DIR/run"
readonly TOOLS_DIR="$FLUX_DIR/tools"
readonly MODPROP="$MODPATH/module.prop"

# ==============================================================================
# [ Helper Functions ]
# ==============================================================================

# Note: ui_print is provided by Magisk/KernelSU/APatch installer
ui_error() { ui_print "! $1"; }
ui_success() { ui_print "√ $1"; }

detect_env() {
    ui_print "- Detecting environment..."
    
    if [ "$KSU" = "true" ]; then
        ui_print "  > KernelSU: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (manager)"
        sed -i "s/^name=.*/& (KernelSU)/" "$MODPROP" 2>/dev/null
    elif [ "$APATCH" = "true" ]; then
        ui_print "  > APatch: $APATCH_VER_CODE"
        sed -i "s/^name=.*/& (APatch)/" "$MODPROP" 2>/dev/null
    elif [ -n "$MAGISK_VER" ]; then
        ui_print "  > Magisk: $MAGISK_VER ($MAGISK_VER_CODE)"
    else
        ui_print "  > Unknown Environment"
    fi
}

# ==============================================================================
# [ Universal Volume Key Detection ]
# ==============================================================================

# Simplified countdown loop with getevent timeout
choose_action() {
    local title="$1"
    local default_action="$2"  # true = Yes/Keep, false = No/Reset
    local timeout_sec=10
    local count=0
    
    ui_print " "
    ui_print "● $title"
    ui_print "  Vol [+] : Yes / Keep"
    ui_print "  Vol [-] : No / Reset"
    ui_print "  (Timeout: ${timeout_sec}s)"

    while [ $count -lt $timeout_sec ]; do
        # Capture 1 event with 1s timeout
        timeout 1 getevent -lc 1 2>&1 | grep KEY_VOLUME > "$TMPDIR/events"
        
        if grep -q KEY_VOLUMEUP "$TMPDIR/events"; then
            ui_print "  > Selected: [Yes/Keep]"
            default_action="true"
            break
        elif grep -q KEY_VOLUMEDOWN "$TMPDIR/events"; then
            ui_print "  > Selected: [No/Reset]"
            default_action="false"
            break
        fi
        count=$((count + 1))
    done
    
    # Show timeout message if loop completed without selection
    [ $count -ge $timeout_sec ] && {
        [ "$default_action" = "true" ] && ui_print "  > Timeout. Default: [Yes/Keep]"
        [ "$default_action" = "false" ] && ui_print "  > Timeout. Default: [No/Reset]"
    }
    
    # Clear event buffer
    timeout 1 getevent -cl >/dev/null 2>&1
    
    [ "$default_action" = "true" ]
}

# Settings keys to migrate (centralized for easy maintenance)
# Note: CORE_TIMEOUT, PROXY_TCP_PORT, PROXY_UDP_PORT, DNS_PORT are now read from config.json
readonly MIGRATE_KEYS="
SUBSCRIPTION_URL
LOG_ENABLE LOG_LEVEL LOG_MAX_SIZE
UPDATE_TIMEOUT RETRY_COUNT UPDATE_INTERVAL
ROUTING_MARK
PROXY_MODE DNS_HIJACK_ENABLE
MOBILE_INTERFACE WIFI_INTERFACE HOTSPOT_INTERFACE USB_INTERFACE
PROXY_MOBILE PROXY_WIFI PROXY_HOTSPOT PROXY_USB PROXY_TCP PROXY_UDP PROXY_IPV6
APP_PROXY_ENABLE APP_PROXY_MODE PROXY_APPS_LIST BYPASS_APPS_LIST
BYPASS_CN_IP CN_IP_URL CN_IPV6_URL
MAC_FILTER_ENABLE MAC_PROXY_MODE PROXY_MACS_LIST BYPASS_MACS_LIST
SKIP_CHECK_FEATURE
"

migrate_settings() {
    local backup_file="$1"
    local target_file="$2"
    
    [ ! -f "$backup_file" ] && return
    
    ui_print "  > Migrating settings (incremental)..."
    
    for key in $MIGRATE_KEYS; do
        # Use awk to extract value (handles multi-line quoted values)
        local value
        value=$(awk -v key="$key" '
            BEGIN { found=0; in_quotes=0; value="" }
            $0 ~ "^"key"=" {
                found=1
                # Get everything after KEY=
                sub("^"key"=", "")
                value = $0
                # Count quotes to detect multi-line
                n = gsub(/"/, "\"", value)
                if (n == 1) {
                    # Opening quote but no closing - multi-line value
                    in_quotes=1
                } else {
                    # Single line value - print and exit
                    print value
                    exit
                }
                next
            }
            found && in_quotes {
                value = value "\n" $0
                # Check for closing quote
                if (/"/) {
                    in_quotes=0
                    print value
                    exit
                }
            }
        ' "$backup_file")
        
        if [ -n "$value" ]; then
            # Create temp file for the replacement
            local tmp_file
            tmp_file=$(mktemp)
            
            # Use awk to replace or append the key in target file
            awk -v key="$key" -v newval="$value" '
                BEGIN { found=0; skip=0 }
                $0 ~ "^"key"=" {
                    found=1
                    print key"="newval
                    # Check if value continues on next lines
                    n = gsub(/"/, "\"", $0)
                    if (n == 1) skip=1
                    next
                }
                skip {
                    if (/"/) skip=0
                    next
                }
                { print }
                END {
                    if (!found) print key"="newval
                }
            ' "$target_file" > "$tmp_file"
            
            mv -f "$tmp_file" "$target_file"
            ui_print "     ↳ $key: restored"
        fi
    done
}

# --- Main Installation Logic ---

main() {
    detect_env
    
    # 1. Backup config files before overwriting
    local TMP_BACKUP
    TMP_BACKUP=$(mktemp -d)
    
    local has_settings=false
    local has_config=false
    local has_pref=false
    local has_singbox=false
    local has_timestamp=false
    
    if [ -d "$FLUX_DIR" ]; then
        ui_print "- Backing up configuration files..."
        
        # Backup settings.ini (will auto-migrate)
        if [ -f "$CONF_DIR/settings.ini" ]; then
            cp -f "$CONF_DIR/settings.ini" "$TMP_BACKUP/settings.ini"
            has_settings=true
        fi
        # Backup config.json (user choice) - with state file
        if [ -f "$CONF_DIR/config.json" ]; then
            cp -f "$CONF_DIR/config.json" "$TMP_BACKUP/config.json"
            has_config=true
            # Also backup state file if exists (contains last_update timestamp)
            if [ -f "$FLUX_DIR/.state" ]; then
                cp -f "$FLUX_DIR/.state" "$TMP_BACKUP/.state"
                has_timestamp=true
            fi
        fi
        # Backup pref.toml (user choice)
        if [ -f "$TOOLS_DIR/pref.toml" ]; then
            cp -f "$TOOLS_DIR/pref.toml" "$TMP_BACKUP/pref.toml"
            has_pref=true
        fi
        # Backup singbox.json template (user choice)
        if [ -f "$TOOLS_DIR/base/singbox.json" ]; then
            cp -f "$TOOLS_DIR/base/singbox.json" "$TMP_BACKUP/singbox.json"
            has_singbox=true
        fi
    fi
    
    # 2. Extract module files to MODPATH (for Magisk)
    # Note: META-INF is handled automatically by Magisk installer, do not extract manually
    ui_print "- Extracting module files..."
    unzip -o "$ZIPFILE" 'module.prop' 'service.sh' 'webroot/*' -d "$MODPATH" >&2
    
    # 3. Clear and recreate FLUX_DIR structure (ensures clean install)
    ui_print "- Installing Flux core files..."
    
    # Remove old directories that will be fully replaced
    rm -rf "$BIN_DIR" "$SCRIPTS_DIR" "$TOOLS_DIR" 2>/dev/null
    
    # Create fresh directory structure
    mkdir -p "$FLUX_DIR" "$CONF_DIR" "$BIN_DIR" "$SCRIPTS_DIR" "$TOOLS_DIR" "$RUN_DIR"
    
    # Extract core files (bin, scripts, conf, tools) - full overwrite
    unzip -o "$ZIPFILE" 'bin/*' 'scripts/*' 'conf/*' 'tools/*' -d "$FLUX_DIR" >&2
    
    # 4. Handle configuration restoration
    ui_print " "
    ui_print "=== Configuration ==="
    
    # 4.1 settings.ini - Auto migrate (no user confirmation needed)
    if [ "$has_settings" = "true" ]; then
        ui_print "- Migrating settings.ini..."
        migrate_settings "$TMP_BACKUP/settings.ini" "$CONF_DIR/settings.ini"
    else
        ui_print "- Using default settings.ini"
    fi
    
    # 4.2 config.json + state file - User choice (synced together)
    if [ "$has_config" = "true" ]; then
        if choose_action "Keep [config.json]?" "true"; then
            cp -f "$TMP_BACKUP/config.json" "$CONF_DIR/config.json"
            # Restore state file (contains last_update) if it was backed up
            if [ "$has_timestamp" = "true" ]; then
                cp -f "$TMP_BACKUP/.state" "$FLUX_DIR/.state"
            fi
            ui_print "  > config.json: restored"
        else
            # Reset config.json means also reset state file
            rm -f "$FLUX_DIR/.state" 2>/dev/null
            ui_print "  > config.json: reset to default"
        fi
    fi
    
    # 4.3 pref.toml - User choice
    if [ "$has_pref" = "true" ]; then
        if choose_action "Keep [pref.toml]?" "true"; then
            cp -f "$TMP_BACKUP/pref.toml" "$TOOLS_DIR/pref.toml"
            ui_print "  > pref.toml: restored"
        else
            ui_print "  > pref.toml: reset to default"
        fi
    fi
    
    # 4.4 singbox.json - User choice
    if [ "$has_singbox" = "true" ]; then
        if choose_action "Keep [singbox.json]?" "true"; then
            mkdir -p "$TOOLS_DIR/base"
            cp -f "$TMP_BACKUP/singbox.json" "$TOOLS_DIR/base/singbox.json"
            ui_print "  > singbox.json: restored"
        else
            ui_print "  > singbox.json: reset to default"
        fi
    fi
    
    # 5. Set Permissions
    ui_print "- Setting permissions..."
    set_perm_recursive "$MODPATH" 0 0 0755 0644
    set_perm_recursive "$FLUX_DIR" 0 0 0755 0644
    
    # Executables
    set_perm_recursive "$BIN_DIR" 0 0 0755 0755
    set_perm_recursive "$SCRIPTS_DIR" 0 0 0755 0755
    chmod +x "$TOOLS_DIR/jq" 2>/dev/null
    chmod +x "$TOOLS_DIR/subconverter" 2>/dev/null
    
    # RUN_DIR needs write access for runtime files
    chmod 0755 "$RUN_DIR"
    
    # 6. Cleanup
    rm -rf "$TMP_BACKUP"
    rm -rf "$FLUX_DIR/tmp" 2>/dev/null
    
    ui_success "Installation Complete!"
}

main
