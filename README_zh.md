# Flux

![Flux Banner](flux_banner.png)

[English](README.md) | [简体中文](README_zh.md)

> 无缝重定向您的网络流量。

一个强大的 Android 透明代理模块，由 [sing-box](https://sing-box.sagernet.org/) 驱动，专为 Magisk / KernelSU / APatch 设计。

> [!IMPORTANT]
> **Flux v1.0.0 现已发布！** 此版本是完整的架构重写，专注于工业级性能和事件驱动编排。查看 [CHANGELOG.md](CHANGELOG.md) 了解从 v0.9.0 开始的全过程。

## 功能特性

### 核心组件
- **sing-box 集成**：使用 sing-box 作为核心代理引擎
- **内置订阅转换**：自动订阅转换和节点过滤
- **jq 处理器**：用于生成配置的 JSON 处理

### 架构与优化
- **多层缓存系统**：基于指纹的高级缓存引擎（内核/规则/配置/元数据），最大限度减少 I/O 和 CPU 开销。
- **事件驱动编排**：使用 `inotifyd` 和中央 `dispatcher` 对状态变化进行反应式、高速响应。
- **原子可靠层**：所有关键配置和模块更新均采用临时交换（temp-and-swap）策略，确保 100% 数据完整性。
- **透明逻辑**：通过精细的 `jq` 模式对各种 `sing-box` 配置进行原生速度的 JSON 解析。

### 代理模式
- **TPROXY**（默认）：高性能透明代理，支持完整的 TCP/UDP。
- **REDIRECT**：针对不支持 TPROXY 的旧内核的可靠回退方案。
- **自动检测**：基于缓存的内核能力进行智能模式选择。
- **智能提取**：自动解析 sing-box `config.json` 中的 `mixed`/`tproxy`/`redirect` 入站和端口。

### 网络支持
- **双栈**：完整的 IPv4 和 IPv6 代理支持
- **DNS 劫持**：TProxy/Redirect 模式下的 DNS 拦截
- **FakeIP ICMP 修复**：使 ping 在 FakeIP DNS 下正常工作

### 接口控制
每个网络接口的独立代理开关：
- 移动数据 (`rmnet_data+`)
- Wi-Fi (`wlan0`)
- 热点 (`wlan2`)
- USB 共享 (`rndis+`)

### 过滤机制
- **按应用代理**：基于 UID 的黑白名单模式（含缓存）
- **MAC 过滤**：热点客户端的 MAC 地址过滤
- **防环路**：内置路由标记和用户组保护，防止流量环路
- **动态 IP 监控**：使用刷新+重新添加（flush+re-add）策略自动处理临时 IPv6 地址

### 订阅管理
- 自动下载、转换和配置生成
- 按地区过滤节点（通过 `country_map.json` 进行基于正则的国家匹配）
- 具有智能缓存的可配置更新间隔
- 通过 `updater.sh` 手动强制更新

### 交互方式
- **[音量+] / [音量-]**：在安装过程中选择是否保留现有配置
- **模块开关**：通过 Magisk 管理器启用/禁用（基于 inotify 的反应式处理）
- **更新订阅**：若已超过 `UPDATE_INTERVAL`，则在启动时自动更新；运行 `updater.sh` 手动更新
- **Web 面板**：Zashboard UI 位于 `http://127.0.0.1:9090/ui/`

---

## 目录结构

所有模块文件位于 `/data/adb/flux/`：

```
/data/adb/flux/
├── bin/
│   └── sing-box              # sing-box 核心二进制文件
│
├── conf/
│   ├── config.json           # 生成的 sing-box 配置
│   └── settings.ini          # 用户配置文件
│
├── run/
│   ├── flux.log              # 模块运行日志（带轮转）
│   ├── sing-box.pid          # sing-box 进程 PID
│   ├── ipmonitor.pid         # IP 监控进程 PID
│   ├── ipmonitor.fifo        # IP 监控命名管道
│   └── event/                # 内部事件信号
│
├── scripts/
│   ├── cache                 # 缓存管理器（验证与签名生成）
│   ├── config                # 配置加载器与 JSON 提取器
│   ├── const                 # 中央路径和常量定义
│   ├── core                  # sing-box 进程控制
│   ├── dispatcher            # 中央事件处理器 (inotifyd)
│   ├── init                  # 环境与完整性初始化
│   ├── iphandler             # 接口本地 IP 同步
│   ├── ipmonitor             # 后台网络变化守护进程
│   ├── log                   # 闪存友好型日志与属性管理
│   ├── rules                 # 高效 IPTables 规则生成器
│   ├── tproxy                # TProxy/Redirect 路由编排
│   └── updater.sh            # 订阅同步与配置合并
│
└── tools/
    ├── base/
    │   ├── country_map.json  # 节点过滤的国家正则映射
    │   └── singbox.json      # sing-box 配置模板
    ├── jq                    # 用于 JSON 处理的 jq 二进制文件
    ├── pref.toml             # Subconverter 首选项
    └── subconverter          # Subconverter 二进制文件

```

### Magisk 模块目录 (`/data/adb/modules/flux/`)

```
/data/adb/modules/flux/
├── webroot/
│   └── index.html            # 重定向至面板 UI
├── service.sh                # 启动服务加载器
├── module.prop               # 模块元数据
└── disable                   # (模块被禁用时创建)
```

---

## 配置说明

主配置文件：`/data/adb/flux/conf/settings.ini`。更改在服务重启后生效。

### 1. 订阅与更新
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `SUBSCRIPTION_URL` | 用于节点转换的订阅链接 | (空) |
| `UPDATE_TIMEOUT` | 下载超时时间（秒） | `15` |
| `UPDATE_INTERVAL` | 自动更新间隔（秒，86400=24h） | `86400` |
| `RETRY_COUNT` | 下载失败重试次数 | `2` |

### 2. 核心与代理模式
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `PROXY_MODE` | `0`=自动, `1`=TProxy, `2`=Redirect | `0` |
| `DNS_HIJACK_ENABLE` | `0`=关闭, `1`=TProxy, `2`=Redirect | `1` |
| `PROXY_TCP` | 启用/禁用 TCP 代理 | `1` |
| `PROXY_UDP` | 启用/禁用 UDP 代理 | `1` |
| `PROXY_IPV6` | 启用/禁用 IPv6 代理 | `0` |
| `ROUTING_MARK` | 路由规则的 Fwmark | `2025` |

### 3. 接口控制
定义 Flux 应监控并拦截的接口。
| 选项 | 描述 | 默认接口名 |
|--------|-------------|-----------------|
| `MOBILE_INTERFACE` | 移动数据接口模式 | `rmnet_data+` |
| `WIFI_INTERFACE` | Wi-Fi 接口名 | `wlan0` |
| `HOTSPOT_INTERFACE` | 热点接口名 | `wlan2` |
| `USB_INTERFACE` | USB 共享接口模式 | `rndis+` |

**开关 (0=绕过, 1=代理):**
`PROXY_MOBILE`, `PROXY_WIFI`, `PROXY_HOTSPOT`, `PROXY_USB`

### 4. 按应用过滤
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `APP_PROXY_ENABLE` | 启用基于应用的过滤 | `0` |
| `APP_PROXY_MODE` | `1`=黑名单 (绕过), `2`=白名单 (仅代理) | `1` |
| `PROXY_APPS_LIST` | 代理应用列表 (空格/换行分隔) | (空) |
| `BYPASS_APPS_LIST` | 绕过应用列表 (空格/换行分隔) | (空) |

### 5. MAC 过滤 (热点客户端)
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `MAC_FILTER_ENABLE` | 启用热点 MAC 过滤 | `0` |
| `MAC_PROXY_MODE` | `1`=黑名单, `2`=白名单 | `1` |
| `PROXY_MACS_LIST` | 代理的客户端 MAC 列表 | (空) |
| `BYPASS_MACS_LIST` | 绕过的客户端 MAC 列表 | (空) |

### 6. 日志与高级设置
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `LOG_LEVEL` | `0`=关闭, `1`=错误, `2`=警告, `3`=信息, `4`=调试 | `3` |
| `LOG_MAX_SIZE` | 日志轮转前的最大尺寸 (字节) | `1048576` |
| `DEBOUNCE_INTERVAL` | 网络变化批处理时间（秒） | `10` |
| `SKIP_CHECK_FEATURE`| 跳过内核能力检测 | `0` |

---

## 安装

1. 从 [Releases](https://github.com/Chth1z/Flux/releases) 下载最新的发布 ZIP 压缩包
2. 通过 Magisk 管理器 / KernelSU / APatch 安装
3. 安装过程中：
   - 按 **[音量+]** 保留现有配置
   - 按 **[音量-]** 使用全新的默认配置
4. 在 `/data/adb/flux/conf/settings.ini` 中配置您的订阅链接
5. 重启以启动

---

## 免责声明

- 本项目仅供教育和研究目的使用。请勿用于非法用途。
- 修改系统网络设置可能会导致不稳定或冲突，请自行承担风险。
- 开发者不对因使用本模块而导致的任何数据丢失或设备损坏负责。

---

## 鸣谢

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - 通用代理平台
- [taamarin/box_for_magisk](https://github.com/taamarin/box_for_magisk) - Magisk 模块模式与灵感
- [CHIZI-0618/box4magisk](https://github.com/CHIZI-0618/box4magisk) - Magisk 模块参考
- [asdlokj1qpi233/subconverter](https://github.com/asdlokj1qpi233/subconverter) - 订阅格式转换器
- [jqlang/jq](https://github.com/jqlang/jq) - 命令行 JSON 处理器

---

## 许可证

[GPL-3.0](LICENSE)
