# Flux

[English](README.md) | [简体中文](README_zh.md)

> Seamlessly redirect your network traffic.

Flux is an Android transparent proxy module powered by [sing-box](https://sing-box.sagernet.org/) for Magisk / KernelSU / APatch.

## Features

- TPROXY-based transparent proxy for TCP/UDP
- Runtime config cache for fast startup
- Event-driven orchestration via `inotifyd`
- Per-interface proxy switches (`rmnet_data+`, `wlan0`, `wlan2`, `rndis+`)
- Per-app filter (blacklist / whitelist) by UID
- Built-in subscription update pipeline (`updater.sh`)
- Dynamic route-address sync via `addrsyncd`
- Web dashboard at `http://127.0.0.1:9090/ui/`

## Runtime Architecture

Boot flow:
1. `flux_service.sh` waits for Android boot completion.
2. `inotifyd` dispatches module/config events to `scripts/dispatcher`.
3. `scripts/init` validates environment, updates config if needed, and builds cache.
4. `scripts/core`, `scripts/tproxy`, and `scripts/addrsync` start in parallel.

Core scripts:
- `scripts/init`: environment prep + cache build
- `scripts/core`: sing-box lifecycle
- `scripts/tproxy`: iptables/ip rule apply & cleanup
- `scripts/addrsync`: addrsyncd lifecycle
- `scripts/dispatcher`: event routing and component coordination
- `scripts/updater.sh`: subscription fetch/transform/deploy

## Directory Layout

`/data/adb/flux/`:

```text
bin/
  addrsyncd
  check_kernel_features.sh
  flux_ingress.bpf.o
  flux_sockaddr.bpf.o
  fluxebpfd
  jq
  sing-box
conf/
  addrsyncd.toml
  bypass_ipv4.txt
  bypass_ipv6.txt
  ebpf.yaml
  config.json
  settings.ini
  template.json
run/
  addrsyncd.log
  addrsyncd.pid
  event/
  flux.log
  sing-box.log
  sing-box.pid
scripts/
  addrsync
  config
  core
  dispatcher
  init
  lib
  log
  rules
  tproxy
  updater.sh
```

Module directory (`/data/adb/modules/flux/`):

```text
disable
flux_service.sh
module.prop
webroot/index.html
```

## Installation

1. Download latest release ZIP from [Releases](https://github.com/Chth1z/Flux/releases)
2. Install via Magisk Manager / KernelSU / APatch
3. Configure subscription URL in `/data/adb/flux/conf/settings.ini`
4. Reboot

During installation:
- `Vol+`: keep existing `template.json` / `addrsyncd.toml`
- `Vol-`: reset to defaults

## Configuration

Main config file: `/data/adb/flux/conf/settings.ini`

### General
| Key | Description | Default |
|---|---|---|
| `SUBSCRIPTION_URL` | Subscription URL | `""` |
| `UPDATE_TIMEOUT` | Download timeout (seconds) | `5` |
| `RETRY_COUNT` | Download retries | `2` |
| `UPDATE_INTERVAL` | Auto-update interval (seconds, `0` = disabled) | `86400` |
| `PREF_CLEANUP_EMOJI` | Remove emoji from node names (`0/1`) | `1` |

### Logging
| Key | Description | Default |
|---|---|---|
| `LOG_LEVEL` | `0`=off, `1`=error, `2`=warn, `3`=info, `4`=debug | `3` |
| `LOG_MAX_SIZE` | Max log size before rotation (bytes) | `1048576` |

### Core
| Key | Description | Default |
|---|---|---|
| `CORE_USER` | sing-box user | `"root"` |
| `CORE_GROUP` | sing-box group | `"root"` |
| `CORE_TIMEOUT` | Startup/stop timeout (seconds) | `5` |

### Interfaces
| Key | Description | Default |
|---|---|---|
| `MOBILE_INTERFACE` | Mobile interface pattern | `"rmnet_data+"` |
| `WIFI_INTERFACE` | Wi-Fi interface | `"wlan0"` |
| `HOTSPOT_INTERFACE` | Hotspot interface | `"wlan2"` |
| `USB_INTERFACE` | USB tethering interface pattern | `"rndis+"` |

### Proxy Control
| Key | Description | Default |
|---|---|---|
| `PROXY_MOBILE` | Proxy mobile traffic (`0/1`) | `1` |
| `PROXY_WIFI` | Proxy Wi-Fi traffic (`0/1`) | `1` |
| `PROXY_HOTSPOT` | Proxy hotspot traffic (`0/1`) | `1` |
| `PROXY_USB` | Proxy USB tethering traffic (`0/1`) | `1` |
| `PROXY_IPV6` | Enable IPv6 proxy (`0/1`) | `0` |

### Routing / App Filter
| Key | Description | Default |
|---|---|---|
| `ROUTING_MARK` | Optional bypass mark override | `""` |
| `APP_PROXY_MODE` | `0`=off, `1`=blacklist, `2`=whitelist | `0` |
| `APP_LIST` | Package list (space/newline separated) | `""` |

### Performance
| Key | Description | Default |
|---|---|---|
| `MSS_CLAMP_ENABLE` | Enable TCP MSS clamp (`0/1`) | `1` |
| `EXCLUDE_INTERFACES` | Explicit output bypass interfaces | `""` |

### Advanced Updater
| Key | Description | Default |
|---|---|---|
| `UPDATER_EXCLUDE_REMARKS` | Regex to exclude nodes | preset |
| `UPDATER_RENAME_RULES` | JSON rename rules | preset |
| `UPDATER_MAX_TAG_LENGTH` | Max node tag length | `32` |

Runtime-derived (read-only in cache):
- `PROXY_PORT`
- `FAKEIP_V4_RANGE`
- `FAKEIP_V6_RANGE`

Note:
- IPv4/IPv6 bypass CIDR lists are now external files (`conf/bypass_ipv4.txt`, `conf/bypass_ipv6.txt`) consumed by `fluxebpfd`.
- `scripts/rules` no longer embeds bypass CIDR matching logic; bypass decisions come from eBPF marks.

## Manual Commands

On device:

```sh
sh /data/adb/flux/scripts/updater.sh update
sh /data/adb/flux/scripts/addrsync status
```

## Disclaimer

- For education/research purposes only.
- Use at your own risk.

## Credits

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [jqlang/jq](https://github.com/jqlang/jq)

## License

[GPL-3.0](LICENSE)
