#!/system/bin/sh

# ==============================================================================
# [ Flux Module Installer ]
# Description: Magisk/KernelSU/APatch installation, migration, and env detection.
# ==============================================================================

SKIPUNZIP=1

# Environment Check

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

# Detect service.d path (KSU <10683 uses different path)
if [ "$KSU" = "true" ] && [ "$KSU_VER_CODE" -lt 10683 ]; then
    SERVICE_DIR="/data/adb/ksu/service.d"
else
    SERVICE_DIR="/data/adb/service.d"
fi

# ==============================================================================
# [ Installer UI Helpers ]
# ==============================================================================

# Note: ui_print is provided by Magisk/KernelSU/APatch installer
ui_error() { ui_print "! $1"; }
ui_success() { ui_print "√ $1"; }

_detect_env() {
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

# Simplified countdown loop with getevent timeout
_choose_action() {
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

# ==============================================================================
# [ Settings Migration Engine ]
# ==============================================================================

# Incremental settings migration logic to preserve user configuration across updates.
# Implementation Note: Uses AWK to safely extract values from existing .ini files,
# supporting multi-line quoted values and ensuring atomic replacement in the new config.
# Note: CORE_TIMEOUT, PROXY_TCP_PORT, PROXY_UDP_PORT, DNS_PORT are now read from config.json
readonly MIGRATE_KEYS="
SUBSCRIPTION_URL UPDATE_TIMEOUT RETRY_COUNT UPDATE_INTERVAL
LOG_LEVEL LOG_MAX_SIZE
CORE_USER CORE_GROUP CORE_TIMEOUT
PROXY_MODE DNS_HIJACK_ENABLE DNS_PORT
MOBILE_INTERFACE WIFI_INTERFACE HOTSPOT_INTERFACE USB_INTERFACE
PROXY_MOBILE PROXY_WIFI PROXY_HOTSPOT PROXY_USB PROXY_TCP PROXY_UDP PROXY_IPV6
TABLE_ID MARK_VALUE MARK_VALUE6 ROUTING_MARK
APP_PROXY_MODE APP_LIST
SKIP_CHECK_FEATURE ENABLE_CONNTRACK MSS_CLAMP_ENABLE DEBOUNCE_INTERVAL EXCLUDE_INTERFACES
"

_migrate_settings() {
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

# ==============================================================================
# [ Main Installation Orchestration ]
# ==============================================================================

main() {
    _detect_env
    
    # 1. Backup config files before overwriting
    local TMP_BACKUP; TMP_BACKUP=$(mktemp -d)
    
    local has_settings=false has_config=false has_pref=false has_singbox=false
    
    if [ -d "$FLUX_DIR" ]; then
        ui_print "- Backing up configuration files..."
        
        # Backup settings.ini (will auto-migrate)
        if [ -f "$CONF_DIR/settings.ini" ]; then
            cp -f "$CONF_DIR/settings.ini" "$TMP_BACKUP/settings.ini"
            has_settings=true
        fi
        # Backup config.json (user choice)
        if [ -f "$CONF_DIR/config.json" ]; then
            cp -f "$CONF_DIR/config.json" "$TMP_BACKUP/config.json"
            has_config=true
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
    ui_print "- Extracting module files..."
    unzip -o "$ZIPFILE" 'module.prop' 'webroot/*' -d "$MODPATH" >&2
    
    # Deploy flux_service.sh to service.d
    mkdir -p "$SERVICE_DIR"
    unzip -o "$ZIPFILE" 'flux_service.sh' -d "$SERVICE_DIR" >&2
    
    # 3. Clear and recreate FLUX_DIR structure
    ui_print "- Installing Flux core files..."
    rm -rf "$BIN_DIR" "$SCRIPTS_DIR" "$TOOLS_DIR" 2>/dev/null
    mkdir -p "$FLUX_DIR" "$CONF_DIR" "$BIN_DIR" "$SCRIPTS_DIR" "$TOOLS_DIR" "$RUN_DIR"
    unzip -o "$ZIPFILE" 'bin/*' 'scripts/*' 'conf/*' 'tools/*' -d "$FLUX_DIR" >&2
    
    # 4. Handle configuration restoration
    ui_print " "
    ui_print "=== Configuration ==="
    
    # 4.1 settings.ini - Auto migrate
    if [ "$has_settings" = "true" ]; then
        ui_print "- Migrating settings.ini..."
        _migrate_settings "$TMP_BACKUP/settings.ini" "$CONF_DIR/settings.ini"
    else
        ui_print "- Using default settings.ini"
    fi
    
    # 4.2 config.json - User choice
    if [ "$has_config" = "true" ]; then
        if _choose_action "Keep [config.json]?" "true"; then
            cp -f "$TMP_BACKUP/config.json" "$CONF_DIR/config.json"
            ui_print "  > config.json: restored"
        else
            ui_print "  > config.json: reset to default"
        fi
    fi
    
    # 4.3 pref.toml - User choice
    if [ "$has_pref" = "true" ]; then
        if _choose_action "Keep [pref.toml]?" "true"; then
            cp -f "$TMP_BACKUP/pref.toml" "$TOOLS_DIR/pref.toml"
            ui_print "  > pref.toml: restored"
        else
            ui_print "  > pref.toml: reset to default"
        fi
    fi
    
    # 4.4 singbox.json - User choice
    if [ "$has_singbox" = "true" ]; then
        if _choose_action "Keep [singbox.json]?" "true"; then
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
    set_perm_recursive "$BIN_DIR" 0 0 0755 0700
    set_perm_recursive "$SCRIPTS_DIR" 0 0 0755 0700
    set_perm_recursive "$TOOLS_DIR" 0 0 0755 0700
    set_perm "$SERVICE_DIR/flux_service.sh" 0 0 0700
    
    # Fallback: fix set_perm_recursive not working on some phones
    chmod ugo+x "$BIN_DIR"/* 2>/dev/null
    chmod ugo+x "$SCRIPTS_DIR"/* 2>/dev/null
    chmod ugo+x "$TOOLS_DIR/jq" "$TOOLS_DIR/subconverter" 2>/dev/null
    
    # 6. Cleanup
    rm -rf "$TMP_BACKUP"
    rm -rf "$FLUX_DIR/tmp" 2>/dev/null
    
    ui_success "Installation Complete!"
}

main
