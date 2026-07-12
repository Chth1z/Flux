# Flux

[English](README.md) | [简体中文](README_zh.md)

> 无缝重定向您的网络流量。

一个强大的 Android 透明代理模块，由 [sing-box](https://sing-box.sagernet.org/) 驱动，专为 Magisk / KernelSU / APatch 设计。

## 功能特性

### 核心组件
- **sing-box 集成**：使用 sing-box 作为核心代理引擎
- **内置订阅转换器**：自动订阅转换和节点过滤
- **jq 处理器**：用于生成配置的 JSON 处理

### 架构与优化
- **SRI (选择性路由注入器)**：统一的 AWK 引擎，整合初始同步与实时监控，通过三层 IP 过滤实现去冗余规则操作
- **高性能数据包漏斗**：三层过滤（物理绕过 → 状态直连 → 有界 Goto 骨架）实现可预测的内核处理路径
- **有界 Goto 骨架**：大规模 CIDR/IP 绕过列表通过自定义 CIDR 规范化、固定层级 goto 树和硬链路预算保持纯 iptables fallback 的稳定性
- **基于 inotify 的缓存**：实时配置监控，即时缓存失效
- **原子可靠性**：所有关键操作采用 temp-and-swap 策略，确保 100% 数据完整性

### 代理模式
- **TPROXY**（默认）：高性能、协议无关的透明代理 (TCP/UDP)。
- **智能探测**：自动解析 sing-box `config.json` 获取 `mixed`/`tproxy` 入站端口。

### 过滤机制
- **按应用代理**：基于 UID 的黑白名单模式（含缓存）
- **防环路**：内置路由标记和用户组保护，防止流量环路
- **动态 IP 监控**：统一的 AWK 引擎配合内存状态去重，自动处理临时 IPv6 地址

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

## 安装

1. 从 [Releases](https://github.com/Chth1z/Flux/releases) 下载最新的发布 ZIP 压缩包
2. 通过 Magisk 管理器 / KernelSU / APatch 安装
3. 安装过程中：
- 按 **[音量+]** 保留现有配置
- 按 **[音量-]** 使用全新的默认配置
4. 在 `/data/adb/flux/conf/settings.ini` 中配置您的订阅链接
5. 重启以启动

---

## 工作流程可视化

### 1. 模块启动与生命周期
展示从 Android 引导、事件监听、环境校验到双驱并行启动的全过程：

```mermaid
graph TD
    Boot([Android 启动]) --> Wait{系统就绪?}
    Wait -->|是| Dispatcher[启动 Dispatcher<br/>inotifyd]

    Dispatcher --> Watch{{监听 disable 文件}}

    Watch -- "已删除" --> Init

    subgraph InitPhase ["初始化阶段"]
        Init[scripts/init] --> Check1{更新过期?}
        Check1 -->|过期| Update[运行 Updater]
        Check1 -->|有效| Check2
        Update --> Check2{缓存有效?}
        Check2 -->|无效| Rebuild[重建缓存]
        Check2 -->|有效| LogRot[日志轮转]
        Rebuild --> LogRot
    end

    LogRot --> Launch["启动所有组件"]

    subgraph Components ["并行启动"]
        Launch --> Core[Core<br/>sing-box]
        Launch --> TProxy[TProxy<br/>iptables]
        Launch --> Monitor[IPMonitor<br/>SRI]
    end

    Core & TProxy --> Ready
    Ready[全部就绪] --> Final([就绪])

    Watch -- "已创建" --> Stop[停止全部]
    Stop --> Cleanup[清理规则]
```

### 2. 极致性能漏斗：数据包分流决策树
展示数据包如何在内核中通过多层快速路径与固定层级前缀决策实现亚秒级精确分流：

```mermaid
graph TD
    Pre([PREROUTING<br/>外部流量]) --> Fast
    Out([OUTPUT<br/>本地应用]) --> Fast

    subgraph Chain ["Mangle 链"]
        Fast{⚡ 快速路径}

        subgraph Shortcuts ["快速路径出口 (Fast-Path)"]
            direction LR
            Recover[还原标记 + TPROXY]
            Accepted[Accepted]
        end

        %% 代理路径 (左侧)
        Fast -->|"connmark = PROXY"| Recover

        %% 绕过路径 (右侧)
        Fast -->|"connmark = BYPASS"| Accepted

        %% 决策路径 (右侧偏下)
        Fast -- "新连接" --> IPCheck

        IPCheck{IP 绕过列表?<br/>有界 Goto 骨架}
        IPCheck -->|公网| IfCheck
        IPCheck -->|私有/局域网/绕过| SetBypass[标记 BYPASS]

        IfCheck{接口<br/>已启用?}
        IfCheck -->|已启用| AppCheck
        IfCheck -->|已禁用| SetBypass

        AppCheck{应用过滤<br/>UID 匹配?}
        AppCheck -->|代理应用| SetProxy[标记 PROXY<br/>+ TPROXY]
        AppCheck -->|绕过应用| SetBypass
    end

    Recover --> SingBox
    SetProxy --> SingBox

    Accepted --> Bypass
    SetBypass --> Bypass

    subgraph Exit ["流量出口"]
        SingBox([sing-box 引擎])
        Bypass([内核直连])
    end
```

---

## 目录结构

所有模块文件位于 `/data/adb/flux/`：

```
/data/adb/flux/
├── bin/
│   ├── jq                    # JSON 处理器
│   └── sing-box              # 核心代理引擎
│
├── conf/
│   ├── config.json           # 生成的 sing-box 配置
│   ├── flux.toml             # 严格校验的 fluxd 守护进程配置
│   ├── settings.ini          # 用户配置文件
│   └── template.json         # 配置模板
│
├── state/
│   └── administrative-intent.json # 按启动周期持久化的 fluxd 管理意图
│
├── run/
│   ├── flux.log              # 模块运行日志
│   ├── sing-box.pid          # sing-box 进程 PID
│   ├── ipmonitor.pid         # IP 监控进程 PID
│   └── event/                # 内部事件信号
│
└── scripts/
    ├── cache                 # 缓存管理器
    ├── config                # 配置加载器
    ├── const                 # 常量定义
    ├── core                  # 进程控制
    ├── dispatcher            # 事件处理器
    ├── init                  # 初始化
    ├── ipmonitor             # 网络监控
    ├── log                   # 日志系统
    ├── rules                 # IPTables 生成器
    ├── tproxy                # 路由逻辑
    └── updater.sh            # 订阅管理器
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

旧版网络配置仍使用 `/data/adb/flux/conf/settings.ini`。Rust 控制平面使用严格校验的 `/data/adb/flux/conf/flux.toml` 守护进程配置；schema 1 会拒绝未知字段，且 `daemon.fail_policy` 仅接受 `"open"`。目前修改 `flux.toml` 后需要重启守护进程，而 `settings.ini` 仍沿用现有的事件驱动重载流程。

### 1. 基础订阅配置
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `SUBSCRIPTION_URL` | 用于节点转换的订阅链接 | (空) |
| `UPDATE_TIMEOUT` | 下载超时时间（秒） | `5` |
| `RETRY_COUNT` | 下载失败重试次数 | `2` |
| `UPDATE_INTERVAL` | 自动更新间隔（秒，86400=24h, 0=禁用） | `86400` |
| `PREF_CLEANUP_EMOJI` | 移除节点名称中的 Emoji (0=保留, 1=移除) | `1` |

### 2. 日志与调试
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `LOG_LEVEL` | `0`=关闭, `1`=错误, `2`=警告, `3`=信息, `4`=调试 | `3` |
| `LOG_MAX_SIZE` | 日志轮转前的最大尺寸 (字节) | `1048576` |

### 3. 核心进程
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `CORE_USER` | sing-box 执行用户 | `root` |
| `CORE_GROUP` | sing-box 执行用户组 | `root` |
| `CORE_TIMEOUT` | 核心启动超时时间（秒） | `5` |

### 4. 代理引擎
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `PROXY_PORT` | 代理监听端口（自动提取）| `1536` |
| `FAKEIP_RANGE_V4` | FakeIP IPv4 地址范围（自动提取）| `198.18.0.0/15` |
| `FAKEIP_RANGE_V6` | FakeIP IPv6 地址范围（自动提取）| `fc00::/18` |

### 5. 网络接口
| 选项 | 描述 | 默认接口名 |
|--------|-------------|-----------------|
| `MOBILE_INTERFACE` | 移动数据接口模式 (支持 + 通配符) | `rmnet_data+` |
| `WIFI_INTERFACE` | Wi-Fi 接口名 | `wlan0` |
| `HOTSPOT_INTERFACE` | 热点接口名 | `wlan2` |
| `USB_INTERFACE` | USB 共享接口模式 | `rndis+` |

### 6. 代理细粒度控制
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `PROXY_MOBILE` / `PROXY_WIFI` | 接口代理开关 (0=绕过, 1=代理) | `1` |
| `PROXY_HOTSPOT` / `PROXY_USB` | 接口代理开关 (0=绕过, 1=代理) | `0` |
| `PROXY_IPV6` | 启用 IPv6 代理 | `0` |

### 7. 路由标识

> [!WARNING]
> 这些选项仅描述旧版 shell 兼容路径。其 `0xff` 掩码与 Android 低 16 位
> `netId` 字段重叠，不是 Rust 重写可接受的新默认值。原生规划器必须同时获得明确的
> 设备限定 mark 授权和完整实时普查；空扫描结果或显式旧值都不能绕过该授权。

| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `ROUTING_MARK` | 核心直连标记 (为空则使用 UID 匹配) | (空) |

### 8. 应用过滤
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `APP_PROXY_MODE` | `0`=禁用, `1`=黑名单, `2`=白名单 | `0` |
| `APP_LIST` | 应用包名列表 (空格或换行分隔) | (空) |

### 9. 性能与兼容性
| 选项 | 描述 | 默认值 |
|--------|-------------|---------|
| `MSS_CLAMP_ENABLE`| 启用 TCP MSS 钳制 | `1` |
| `BLOCK_QUIC` | 全局阻断 UDP/443 QUIC | `0` |
| `MARK_MASK` | Flux connmark 掩码 | `0xff` |
| `RULE_BACKEND` | 规则后端（生产默认仅 `iptables_restore`） | `iptables_restore` |
| `BYPASS_SET_BACKEND` | 绕过集合后端（`zone`, `ipset`, `auto`） | `zone` |
| `PERFORMANCE_MODE` | 内核支持时启用 socket/conntrack 快路径 | `0` |
| `PRIVATE_DNS_GUARD` | 预留兼容 profile，默认关闭 | `0` |
| `IPV6_FORCE_DISABLE` | 预留兼容 profile，默认关闭 | `0` |
| `VENDOR_FIX_PROFILE` | 预留厂商 profile（`none`, `oneplus`） | `none` |
| `HOTSPOT_FIX` | 预留热点兼容 profile | `0` |
| `EXCLUDE_INTERFACES`| 显式忽略的接口列表 (OUTPUT) | (空) |

### CLI 控制

Flux 提供纯命令行控制入口：

```bash
/data/adb/flux/scripts/fluxctl status
/data/adb/flux/scripts/fluxctl start
/data/adb/flux/scripts/fluxctl stop
/data/adb/flux/scripts/fluxctl restart
/data/adb/flux/scripts/fluxctl diagnose
/data/adb/flux/scripts/fluxctl rules-preview
/data/adb/flux/scripts/fluxctl resync
/data/adb/flux/scripts/fluxctl logs
```

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
- [jqlang/jq](https://github.com/jqlang/jq) - 命令行 JSON 处理器

---

## 许可证

[GPL-3.0](LICENSE)
