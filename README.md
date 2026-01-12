# Flux

> Seamlessly redirect your network flux.

A powerful Android transparent proxy module powered by [sing-box](https://sing-box.sagernet.org/), designed for Magisk / KernelSU / APatch.

## Features

### Core Components
- **sing-box Integration**: Uses sing-box as the core proxy engine
- **Subconverter Built-in**: Automatic subscription conversion and node filtering
- **jq Processor**: JSON manipulation for configuration generation

### Proxy Modes
- **TPROXY** (default): Full TCP/UDP support with transparent proxying
- **REDIRECT**: Fallback mode for kernels without TPROXY support
- **Auto Detection**: Automatically selects the best mode based on kernel capabilities

### Network Support
- **Dual-Stack**: Full IPv4 and IPv6 proxy support
- **DNS Hijacking**: TProxy/Redirect mode DNS interception
- **China IP Bypass**: IPset-based mainland China IP bypass (optional)
- **FakeIP ICMP Fix**: Enables ping to work correctly with FakeIP DNS

### Interface Control
Independent proxy switches for each network interface:
- Mobile Data (`rmnet_data+`)
- Wi-Fi (`wlan0`)
- Hotspot (`wlan2`)
- USB Tethering (`rndis+`)

### Filtering Mechanisms
- **Per-App Proxy**: UID-based blacklist/whitelist mode
- **MAC Filter**: MAC address filtering for hotspot clients
- **Anti-Loopback**: Built-in route marking and user group protection to prevent traffic loops
- **Dynamic IP Monitor**: Automatically handles temporary IPv6 addresses

### Subscription Management
- Automatic download, conversion, and configuration generation
- Node filtering by region (regex-based country matching)
- Configurable update interval with smart caching
- Manual force update via `updater.sh`

### Interaction
- **[Vol+] / [Vol-]**: Choose whether to preserve configuration during installation
- **Module Toggle**: Enable/disable via Magisk Manager (reactive inotify-based)
- **Update Subscription**: Auto-updates on boot if `UPDATE_INTERVAL` has passed; run `updater.sh force` to update manually
- **Web Dashboard**: Zashboard UI at `http://127.0.0.1:9090/ui/`

---

## Directory Structure

All module files are located at `/data/adb/Flux/`:

```
/data/adb/Flux/
├── bin/
│   └── sing-box              # sing-box core binary
│
├── conf/
│   ├── config.json           # Generated sing-box configuration
│   └── settings.ini          # User configuration file
│
├── run/
│   ├── zashboard/            # Web dashboard files
│   ├── sing-box.log          # sing-box core logs
│   ├── Flux.log              # Module runtime logs (with rotation)
│   ├── sing-box.pid          # sing-box process PID
│   ├── ip_monitor.pid        # IP monitor daemon PID
│   ├── cache.db              # sing-box cache database
│   └── .ip_cache             # IP monitor address cache
│
├── scripts/
│   ├── flux.config           # Centralized path definitions & defaults
│   ├── flux.core             # Core lifecycle management (start/stop)
│   ├── flux.ip.monitor       # Dynamic IP address monitor daemon
│   ├── flux.logger           # Advanced logging & prop management
│   ├── flux.mod.inotify      # Module toggle listener (inotifyd)
│   ├── flux.tproxy           # TProxy/Redirect iptables rules
│   ├── start.sh              # Service orchestrator (parallel start/stop)
│   └── updater.sh            # Subscription updater & config generator
│
├── tools/
│   ├── base/
│   │   └── singbox.json      # sing-box configuration template
│   ├── jq                    # jq binary for JSON processing
│   ├── pref.toml             # Subconverter preferences
│   └── subconverter          # Subconverter binary
│
└── state/
    ├── .core_ready           # Core startup completion flag
    ├── .tproxy_ready         # TProxy setup completion flag
    └── .last_update          # Last subscription update timestamp
```

### Magisk Module Directory (`/data/adb/modules/Flux/`)

```
/data/adb/modules/Flux/
├── webroot/
│   └── index.html            # Redirect to dashboard UI
├── service.sh                # Boot service launcher
├── module.prop               # Module metadata
└── disable                   # (Created when module is disabled)
```

---

## Configuration

Main configuration file: `/data/adb/Flux/conf/settings.ini`

### Key Settings

| Option | Description | Default |
|--------|-------------|---------|
| `SUBSCRIPTION_URL` | Subscription URL | (empty) |
| `PROXY_MODE` | 0=Auto, 1=TProxy, 2=Redirect | `0` |
| `PROXY_TCP` | Enable TCP proxy | `1` |
| `PROXY_UDP` | Enable UDP proxy | `1` |
| `PROXY_IPV6` | Enable IPv6 proxy | `0` |
| `DNS_HIJACK_ENABLE` | 0=Disable, 1=TProxy, 2=Redirect | `1` |
| `UPDATE_INTERVAL` | Auto-update interval (seconds) | `86400` |

### Interface Proxy Switches

| Option | Description | Default |
|--------|-------------|---------|
| `PROXY_MOBILE` | Proxy mobile data | `1` |
| `PROXY_WIFI` | Proxy Wi-Fi | `1` |
| `PROXY_HOTSPOT` | Proxy hotspot clients | `0` |
| `PROXY_USB` | Proxy USB tethering | `0` |

### Per-App Proxy

| Option | Description | Default |
|--------|-------------|---------|
| `APP_PROXY_ENABLE` | Enable per-app filtering | `0` |
| `APP_PROXY_MODE` | 1=Blacklist, 2=Whitelist | `1` |
| `PROXY_APPS_LIST` | Apps to proxy (whitelist) | (empty) |
| `BYPASS_APPS_LIST` | Apps to bypass (blacklist) | (empty) |

### China IP Bypass

| Option | Description | Default |
|--------|-------------|---------|
| `BYPASS_CN_IP` | Enable China IP bypass | `0` |
| `CN_IP_URL` | IPv4 CIDR list URL | GeoIP2-CN |
| `CN_IPV6_URL` | IPv6 CIDR list URL | ispip.clang.cn |

### MAC Filter (Hotspot Only)

| Option | Description | Default |
|--------|-------------|---------|
| `MAC_FILTER_ENABLE` | Enable MAC filtering | `0` |
| `MAC_PROXY_MODE` | 1=Blacklist, 2=Whitelist | `1` |
| `PROXY_MACS_LIST` | MACs to proxy | (empty) |
| `BYPASS_MACS_LIST` | MACs to bypass | (empty) |

---

## Installation

1. Download the latest release ZIP from [Releases](https://github.com/Chth1z/Flux/releases)
2. Install via Magisk Manager / KernelSU / APatch
3. During installation:
   - Press **[Vol+]** to preserve existing configuration
   - Press **[Vol-]** to use fresh default configuration
4. Configure your subscription URL in `/data/adb/Flux/conf/settings.ini`
5. Reboot to start

---

## Disclaimer

- This project is for educational and research purposes only. Do not use for illegal purposes.
- Modifying system network settings may cause instability or conflicts. Use at your own risk.
- The developer is not responsible for any data loss or device damage caused by using this module.

---

## Credits

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - The universal proxy platform
- [CHIZI-0618/AndroidTProxyShell](https://github.com/CHIZI-0618/AndroidTProxyShell) - Android TProxy shell reference
- [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) - Subscription format converter
- [jqlang/jq](https://github.com/jqlang/jq) - Command-line JSON processor
- [taamarin/box_for_magisk](https://github.com/taamarin/box_for_magisk) - Magisk module patterns and inspiration
- [CHIZI-0618/box4magisk](https://github.com/CHIZI-0618/box4magisk) - Magisk module reference

---

## License

[GPL-3.0](LICENSE)