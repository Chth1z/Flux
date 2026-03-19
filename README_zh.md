# Flux

[English](README.md) | [简体中文](README_zh.md)

> 无缝重定向你的网络流量。

Flux 是一个基于 [sing-box](https://sing-box.sagernet.org/) 的 Android 透明代理模块，适配 Magisk / KernelSU / APatch。

## 功能特性

- 基于 TPROXY 的 TCP/UDP 透明代理
- 运行期配置缓存，提升启动速度
- `inotifyd` 事件驱动编排
- 按接口独立开关代理（`rmnet_data+`、`wlan0`、`wlan2`、`rndis+`）
- 按应用 UID 黑白名单过滤
- 内置订阅更新流水线（`updater.sh`）
- 通过 `addrsyncd` 动态同步路由地址
- Web 面板：`http://127.0.0.1:9090/ui/`

## 运行架构

启动流程：
1. `flux_service.sh` 等待 Android 开机完成。
2. `inotifyd` 将模块/配置事件分发给 `scripts/dispatcher`。
3. `scripts/init` 完成环境校验、按策略更新配置并构建缓存。
4. `scripts/core`、`scripts/tproxy`、`scripts/addrsync` 并行启动。

核心脚本：
- `scripts/init`：初始化与缓存构建
- `scripts/core`：sing-box 生命周期管理
- `scripts/tproxy`：iptables/ip rule 应用与清理
- `scripts/addrsync`：addrsyncd 生命周期管理
- `scripts/dispatcher`：事件分发与组件协调
- `scripts/updater.sh`：订阅下载、转换、部署

## 目录结构

`/data/adb/flux/`：

```text
bin/
  addrsyncd
  jq
  sing-box
conf/
  addrsyncd.toml
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

模块目录（`/data/adb/modules/flux/`）：

```text
disable
flux_service.sh
module.prop
webroot/index.html
```

## 安装

1. 从 [Releases](https://github.com/Chth1z/Flux/releases) 下载最新 ZIP
2. 通过 Magisk Manager / KernelSU / APatch 安装
3. 修改 `/data/adb/flux/conf/settings.ini`，填入订阅地址
4. 重启设备

安装期间：
- `音量+`：保留已有 `template.json` / `addrsyncd.toml`
- `音量-`：恢复默认

## 配置说明

主配置文件：`/data/adb/flux/conf/settings.ini`

### 基础配置
| 键 | 说明 | 默认值 |
|---|---|---|
| `SUBSCRIPTION_URL` | 订阅地址 | `""` |
| `UPDATE_TIMEOUT` | 下载超时（秒） | `5` |
| `RETRY_COUNT` | 下载重试次数 | `2` |
| `UPDATE_INTERVAL` | 自动更新间隔（秒，`0`=禁用） | `86400` |
| `RESTART_DEBOUNCE_SEC` | Restart debounce window (seconds) | `10` |
| `PREF_CLEANUP_EMOJI` | 节点名去除 Emoji（`0/1`） | `1` |

### 日志
| 键 | 说明 | 默认值 |
|---|---|---|
| `LOG_LEVEL` | `0`=关闭，`1`=错误，`2`=警告，`3`=信息，`4`=调试 | `3` |
| `LOG_MAX_SIZE` | 日志轮转阈值（字节） | `1048576` |

### 核心进程
| 键 | 说明 | 默认值 |
|---|---|---|
| `CORE_USER` | sing-box 用户 | `"root"` |
| `CORE_GROUP` | sing-box 组 | `"root"` |
| `CORE_TIMEOUT` | 启停超时（秒） | `5` |

### 网络接口
| 键 | 说明 | 默认值 |
|---|---|---|
| `MOBILE_INTERFACE` | 蜂窝接口匹配 | `"rmnet_data+"` |
| `WIFI_INTERFACE` | Wi-Fi 接口 | `"wlan0"` |
| `HOTSPOT_INTERFACE` | 热点接口 | `"wlan2"` |
| `USB_INTERFACE` | USB 共享接口匹配 | `"rndis+"` |

### 代理控制
| 键 | 说明 | 默认值 |
|---|---|---|
| `PROXY_MOBILE` | 蜂窝是否代理（`0/1`） | `1` |
| `PROXY_WIFI` | Wi-Fi 是否代理（`0/1`） | `1` |
| `PROXY_HOTSPOT` | 热点是否代理（`0/1`） | `1` |
| `PROXY_USB` | USB 共享是否代理（`0/1`） | `1` |
| `PROXY_IPV6` | 是否启用 IPv6 代理（`0/1`） | `0` |

### 路由与应用过滤
| 键 | 说明 | 默认值 |
|---|---|---|
| `ROUTING_MARK` | 可选旁路 mark 覆盖值 | `""` |
| `APP_PROXY_MODE` | `0`=关闭，`1`=黑名单，`2`=白名单 | `0` |
| `APP_LIST` | 应用包名列表（空格/换行分隔） | `""` |

### 性能兼容
| 键 | 说明 | 默认值 |
|---|---|---|
| `MSS_CLAMP_ENABLE` | TCP MSS 钳制（`0/1`） | `1` |
| `EXCLUDE_INTERFACES` | OUTPUT 链显式绕过接口列表 | `""` |

### 更新器高级项
| 键 | 说明 | 默认值 |
|---|---|---|
| `UPDATER_EXCLUDE_REMARKS` | 排除节点正则 | 预设 |
| `UPDATER_RENAME_RULES` | 节点重命名 JSON 规则 | 预设 |
| `UPDATER_MAX_TAG_LENGTH` | 节点名最大长度 | `32` |

运行期缓存中的派生只读项：
- `PROXY_PORT`
- `FAKEIP_V4_RANGE`
- `FAKEIP_V6_RANGE`

说明：
- IPv4/IPv6 绕过 CIDR 列表使用 `scripts/lib` 内置常量，不在 `settings.ini` 暴露。

## 手动命令

设备上可执行：

```sh
sh /data/adb/flux/scripts/updater.sh update
sh /data/adb/flux/scripts/addrsync status
```

## 免责声明

- 仅用于学习与研究。
- 使用风险自负。

## 致谢

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [jqlang/jq](https://github.com/jqlang/jq)

## 许可证

[GPL-3.0](LICENSE)