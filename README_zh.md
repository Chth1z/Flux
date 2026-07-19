# Flux

[English](README.md) | [简体中文](README_zh.md)

> 无缝重定向您的网络流量。

Flux 是面向 Magisk、KernelSU 与 APatch 的 Android 透明代理模块。它将
[sing-box](https://sing-box.sagernet.org/) 作为独立代理引擎，并正在迁移到由单一 Rust
控制器 `fluxd` 统一编排的架构。

## 预发布重写契约

当前 Rust 重写分支仅用于开发，不是可发布模块。在目标运行时完全由 Rust 接管、旧运行时组件全部移除
之前，本分支不会发布公开 bridge、alpha、beta 或 release candidate。只要有助于更快形成干净的 Rust
设计，中间提交可以破坏已经过时的内部 schema 与兼容接口。

当前开发检查点仍是 Phase 1 过渡桥接：

- `fluxd` 负责管理意图、串行生命周期、Generation 恢复以及 Sing-Box 子进程。
- Rust 所有权下的准备阶段只调用 `fluxd render-legacy-rules`，生成保留的 source-shape restore
  缓存，并将其生产者记录为 `rust`；它不会静默回退到 shell 生成器。
- 只有显式旧所有权路径会 source `scripts/rules`，并将缓存生产者记录为 `shell`；该路径是互斥的
  回滚路径，其他情况下 `scripts/rules` 仅作为冻结 oracle 保留。
- `scripts/tproxy` 仍是唯一 restore 执行器和 xtables 内核写入者。在后续所有权切换前，策略路由与
  地址派生规则也仍由 shell 适配器修改。
- 当前开发桥接仅接受 `PROXY_MODE="tproxy"`。TUN 字段为未来单一所有者方案保留，在激活前会被拒绝。
- 当前预发布桥接的抓取验证仍是结构验证。更严格的本地 OUTPUT 功能 canary 已分阶段实现，但尚未构成
  Android 发布资格证据。
- 低于 5.10 的内核保持可查询、不可变更的只读状态。
- Capability Profile schema 2 已能保存精确的 Android 产品、系统构建、vendor 构建、安全补丁、
  verified boot、内核构建、SELinux policy、netd/Connectivity、工具产物及网络命名空间身份。
  device-qualified mark policy 与完整 census 现在必须绑定这套完整且命名空间一致的身份。生产收集器在
  Android 专用收集器和评审 catalog 完成前仍明确报告 unavailable，因此不会新增任何修改权限。
- eBPF 仅是未来可选的观测/加速能力。Flux 不打包 `.ko`、KPM 或不透明内核模块载荷，也不调用
  显式模块加载 API；但当前旧 shell 桥接尚未证明所有 xtables 依赖均已预先启用、不会触发内核隐式
  自动加载。

详细设计和当前门槛见 [`docs/`](docs/README.md)。

临时 shell 组件继续存在，只因为它们仍是某些网络状态唯一已经证明可用的写入者或 oracle；这不是兼容
承诺。每个 Rust 替代组件一旦通过 readback、rollback、recovery、单写入者和 Android 切换门槛，对应
旧运行时组件就应立即删除。最终包只允许保留平台必需的安装、启动、禁用与卸载胶水，而且这些胶水不得包含
网络策略或清理实现。

## 当前能力

- 双栈 TCP/UDP TPROXY 兼容路径。
- 移动网络、Wi-Fi、热点与 USB 共享网络的独立开关。
- 基于 UID 的应用允许/拒绝策略，以及 Android 用户/工作资料范围。
- 通过过渡期独立进程 `addrsyncd` 动态协调本机地址规则。
- Generation 级配置快照、有界回滚和启动恢复。
- 订阅下载、过滤、模板合并和 Sing-Box 配置校验。
- 通过 `fluxd` 私有 Unix socket 提供命令行控制。
- 配置的 Sing-Box API 可用时，可通过 `http://127.0.0.1:9090/ui/` 进入 Zashboard。

## 已发布的旧版本

[Releases](https://github.com/Chth1z/Flux/releases) 页面可能仍包含旧版或不完整的
hybrid/旧政策产物；这些产物都不是“完整 Rust 重写”的发布版。当前分支的 development staging 只用于
受控测试，不得作为可安装的重写版本对外发布。在完整 Rust 发布门槛通过之前，不再发布新的 rewrite
alpha、beta、release candidate 或正式版本。

下方迁移行为仅记录当前临时开发桥接，在正式发布前允许不兼容地调整：

升级时按文件分别处理：

- `flux.toml` 始终保留，因为它是 Rust 控制器的权威配置。
- `settings.ini` 始终迁移到新包所带的 schema。
- `template.json` 与 `addrsyncd.toml` 分别显示独立的音量键保留/重置提示。
- 生成的桥接缓存会被清理；已有 `run/`、`state/` 和生成的 `config.json` 会保留，供启动恢复进行
  协调，后续更新/重载策略再决定何时重新生成 Sing-Box 配置。

即使当前桥接不能激活未来模式，TUN 和多用户配置值也会在升级时保留。解包后的迁移/恢复失败会中止
安装，安装器会先尝试恢复升级前保留的配置，再删除临时备份。

## 运行生命周期

```mermaid
flowchart TD
    Boot["Android late-start"] --> Service["模块内 service.sh"]
    Service --> Watchdog["有界 fluxd watchdog"]
    Watchdog --> Fluxd["fluxd daemon"]
    Service --> Inotify["inotifyd 事实监听"]
    Inotify --> Event["flux-event"]
    Event --> Fluxd
    CLI["fluxctl / fluxd CLI"] --> Socket["私有 Unix 控制 socket"]
    Socket --> Fluxd
    Fluxd --> Coordinator["串行 RuntimeCoordinator"]
    Coordinator --> Engine["EngineSupervisor"]
    Engine --> SingBox["sing-box 子进程"]
    Coordinator --> Bridge["LegacyDispatcher 适配器"]
    Bridge --> Init["scripts/init 准备阶段"]
    Init -->|"仅 Rust 所有权"| Renderer["fluxd render-legacy-rules"]
    Init -->|"仅显式旧所有权"| Oracle["scripts/rules 冻结 oracle / 回滚"]
    Renderer --> Cache["restore 缓存；生产者 = rust"]
    Oracle --> CacheLegacy["restore 缓存；生产者 = shell"]
    Cache --> Tproxy["scripts/tproxy 唯一 restore 执行器"]
    CacheLegacy --> Tproxy
    Tproxy --> Kernel["xtables 内核状态"]
    Bridge --> AddrSync["scripts/addrsync + 独立 addrsyncd"]
    AddrSync --> KernelPolicy["RPDB + 地址派生规则"]
```

Rust 所有权路径中不存在并行 IPMonitor 所有者。事件事实先进入 `fluxd`，所有会修改系统状态的桥接阶段
都在同一个串行 worker 中执行。

显式旧路径重启会先验证最新 settings，重新生成并检查替换用 Sing-Box 配置，并准备好全部替换 restore
缓存，然后才停止当前运行实例。替换准备失败时，正在运行的旧实例保持不变。

## 数据包策略桥接

保留的兼容路径会生成固定的有界 zone iptables 分类器。在 Rust 所有权准备阶段，`scripts/init` 只会
调用 `fluxd render-legacy-rules` 生成 apply/cleanup restore 文档，并在缓存生产者标记中记录 `rust`。
只有需要解析应用 UID 时，`scripts/init` 才会调用
`fluxd snapshot-legacy-packages --source PATH`；该命令以禁止跟随符号链接的方式打开来源，验证有界的
普通稳定描述符，并流式生成一份不可变快照，保证每次渲染观察同一输入。否则会发布空快照而不读取
Android 软件包清单。渲染失败会使准备阶段失败，不会切换写入者或回退到 shell。

只有显式旧所有权路径会 source `scripts/rules`；它将生产者记录为 `shell`，并作为互斥回滚路径存在。
其他情况下该脚本仅作为冻结的字节级 oracle 保留。两条路径都只发布 restore 缓存；在生产桥接路径中，
真正执行缓存和写入网络状态的组件仍只有 `scripts/tproxy`。

当前由实际桥接使用的 Rust 实现是旧兼容/source-shape 渲染器。它复现保留的 shell 契约，包括差分
一致性所需的顺序与重复形式；它不是后端无关 Capture Program 的规范 lowering，也不授予原生写入
权限。已有连接标记走快速路径；新流量依次经过强制/本地绕过、接口策略和应用策略，最后选择直接
放行或交给 Sing-Box 的 TPROXY 监听器。

此外，`flux-platform` 已实现不含扩展的规范 lowerer。仅含转发入口的 Capture Program 保留 schema v1；
包含本地 OUTPUT 的输入使用 schema v2，由私有 `O` 链设置掩码 mark，私有 `P` 链描述经 loopback
重新进入 PREROUTING 的 TPROXY 配套路径，混合程序还可包含 `F` 链。规范产物本身不授予写入权限。

私有 `NativeXtablesOwner` 只暴露 `converge(target)` 与 `recover()`，并在目标经过独立准入后负责稳定的
`FLX{4|6}SP` PREROUTING / `FLX{4|6}SO` OUTPUT 根链、固定描述符的 command/restore/save、精确 xtables
与策略路由 readback、回滚、持久 journal 恢复、清理及 shell 可见的迁移租约。持久 owner payload
schema 2 将目标及可选上一 Generation 绑定到产物摘要、工具集摘要，以及完整 IPv4/IPv6 策略路由审计
摘要；后者包含精确的 loopback 名称/索引身份。每次路由观察或修改前都会双向验证实时的名称到索引和
索引到名称映射；只有 IPv4/IPv6 两套 xtables 与两族路由审计均精确或为空时，才能发布 `Active` 或
`CleanAbsent`，因此未启用族中的残留也会阻止状态推进。

共享 writer fence 使用 shell-owner-v2 记录：父进程 PID/`/proc` 启动 tick、可选子进程 PID/启动 tick，
以及同一个 boot ID。任一参与者仍存活都会保持 busy。父进程绑定的 `addrsync` 或 `tproxy` 修改阶段会串行
使用唯一子进程槽位；子阶段在父进程死亡后仍会继续阻止竞争写入，且不会替换父进程身份。存活父进程可以
回收已死亡的子进程。只有父子均死亡、PID 已复用或记录属于上一 boot 时，才可在精确复核后退休。裸 lock、
格式错误、native/shell 混合 owner 或无法验证的记录都会保持 fail-closed。

当前 boot 的 terminal journal 也不能仅凭磁盘记录直接视为 `CleanAbsent`。恢复会保留 native guard、共享
writer fence 和可能仍存在的 lease，重新证明全局 IPv4/IPv6 xtables 与策略路由均为空，然后才删除 terminal
lease/journal 产物并释放 fence。上一 boot 中精确的 revision-1 `Activating`、已写 journal 但尚未写 lease 的
边界，在 native-owner scope 与 journal 一致且实时空状态证明通过时可以恢复；同一 boot 或 scope 不匹配的
missing-lease 状态继续 fail-closed。所有旧模式 start、stop、restart 与失败清理阶段事务，都会在
`addrsync` 或 `tproxy` 修改前先取得同一个 writer fence。长期运行的 standalone `addrsyncd` 仍属于旧运行时
所有权，必须在生产组件切换时删除。真实 Adapter 已通过确定性测试和一次 rooted WSA Android 13 x86_64
的 apply/recover/stop 机制测试。

生产目标准入仍故意保持为空，因此生产 xtables driver 继续返回 `Unsupported`，`scripts/tproxy` 仍是
生产桥接写入者。WSA 结果只证明机制；Android 5.10/ARM64、mark/RPDB 权威、功能 receipt、daemon 切换
和被替代 shell 职责的删除仍未完成。

`BYPASS_SET_BACKEND="zone"` 是唯一已实现的后端。在独立适配器、能力探测和一致性测试完成前，
`ipset` 与 `auto` 会被明确拒绝。

旧桥接仍使用固定 table/priority `2025` 和低字节 mark。这些值会与 Android mark 策略重叠，不是未来
原生后端可接受的默认值；详见下方“路由 mark”警告。

## 安装目录

运行文件位于 `/data/adb/flux/`：

```text
/data/adb/flux/
├── bin/
│   ├── fluxd                 # Rust 控制器与 CLI
│   ├── addrsyncd             # 过渡期地址规则协调器/回滚二进制
│   ├── jq                    # 桥接 JSON 适配器
│   └── sing-box              # 独立代理引擎
├── conf/
│   ├── flux.toml             # 严格 fluxd schema
│   ├── settings.ini          # 旧网络/订阅设置
│   ├── addrsyncd.toml
│   ├── template.json
│   ├── config.json           # 生成的 Sing-Box 配置
│   └── manifest.json         # 发布 provenance 契约
├── cache/
│   ├── cache_rules_* / cache_cleanup_*  # Rust 或 shell 生成的 restore 文档
│   ├── cache_packages       # Rust 软件包快照；shell 路径中不存在，无需解析时为空
│   └── cache_valid          # 缓存生产者标记：rust 或 shell
├── state/
│   └── administrative-intent.json
├── run/
│   ├── fluxd.sock
│   ├── fluxd.pid
│   ├── fluxd.log
│   ├── generations/          # 不可变的待激活 Generation 快照
│   └── capture.* / engine.*  # Generation 所有权与恢复记录
└── scripts/
    ├── fluxctl               # 兼容 CLI 包装器
    ├── flux-event            # 原始 inotify 事实适配器
    ├── dispatcher            # 串行 shell 阶段适配器
    ├── init / config / updater.sh
    ├── rules                # 冻结 source-shape oracle 与显式旧路径回滚生成器
    ├── tproxy               # 唯一 restore 执行器与 xtables 内核写入者
    ├── addrsync
    └── lib / log / core      # 公共与仅回滚使用的辅助脚本
```

模块管理目录 `/data/adb/modules/flux/` 包含 `service.sh`、`module.prop`、面板重定向页以及由管理器
维护的 `disable` 标记。安装器会移除旧的全局 `/data/adb/*/service.d/flux_service.sh`，确保只有模块内
watchdog 拥有 `fluxd`。

## 配置说明

`flux.toml` 配置 Rust 守护进程。它采用严格 schema：未知或缺失字段会失败，当前修改后需要重启
守护进程。`settings.ini` 配置保留的网络与订阅桥接。

### 订阅与日志

| 选项 | 描述 | 默认值 |
|---|---|---|
| `SUBSCRIPTION_URL` | 订阅地址 | 空 |
| `UPDATE_TIMEOUT` | 下载超时（秒） | `5` |
| `RETRY_COUNT` | 下载重试次数 | `2` |
| `UPDATE_INTERVAL` | 刷新间隔；`0` 禁用自动刷新 | `86400` |
| `PREF_CLEANUP_EMOJI` | 删除节点名称中的 emoji | `1` |
| `LOG_LEVEL` | `0` 关闭至 `4` 调试 | `3` |
| `LOG_MAX_SIZE` | 日志轮转阈值（字节） | `1048576` |

### 代理引擎

| 选项 | 描述 | 默认值 |
|---|---|---|
| `CORE_USER` / `CORE_GROUP` | Sing-Box 执行身份 | `root` / `root` |
| `CORE_TIMEOUT` | 引擎启动超时（秒） | `5` |
| `PROXY_PORT` | TPROXY 监听端口；只从 `tproxy` inbound 自动提取 | `1536` |
| `FAKEIP_V4_RANGE` | FakeIP IPv4 范围 | `198.18.0.0/15` |
| `FAKEIP_V6_RANGE` | FakeIP IPv6 范围 | `fc00::/18` |
| `PROXY_MODE` | 当前桥接模式；仅接受 `tproxy` | `tproxy` |
| `TUN_INTERFACE`、`TUN_INET4_ADDRESS`、`TUN_INET6_ADDRESS`、`TUN_MTU` | 会迁移保留，但 Phase 1 不支持 | 包内默认值 |

`mixed` inbound 不是透明 TPROXY 监听器，因此不会用于自动提取端口。

### 接口与应用范围

| 选项 | 描述 | 默认值 |
|---|---|---|
| `MOBILE_INTERFACE` | 移动网络接口模式 | `rmnet_data+` |
| `WIFI_INTERFACE` | Wi-Fi 接口 | `wlan0` |
| `HOTSPOT_INTERFACE` | 热点接口 | `wlan2` |
| `USB_INTERFACE` | USB 共享接口模式 | `rndis+` |
| `PROXY_MOBILE`、`PROXY_WIFI`、`PROXY_HOTSPOT`、`PROXY_USB` | 各接口代理开关 | `1` |
| `PROXY_IPV6` | 启用 IPv6 代理规则 | `0` |
| `APP_PROXY_MODE` | `0` 禁用，`1` 拒绝列表/绕过列出应用，`2` 允许列表/仅代理列出应用 | `0` |
| `APP_LIST` | 应用包名列表 | 空 |
| `APP_USER_SCOPE` | `owner`、`all` 或 `list` | `owner` |
| `APP_USER_LIST` | `list` 范围使用的 Android 用户 ID | `0` |

### 路由 mark 与兼容字段

> [!WARNING]
> 下表描述旧 shell 桥接。其 `0xff` 掩码与 Android 低 16 位 `netId` 字段重叠，不是原生 Rust
> 规划器可接受的默认值。原生写入必须获得设备限定的 mark 授权，并完成实时冲突普查。

| 选项 | 描述 | 默认值 |
|---|---|---|
| `ROUTING_MARK` | 可选的引擎绕过 mark；为空时使用 owner 匹配 | 空 |
| `MARK_MASK` | 旧 connmark 掩码 | `0xff` |
| `RULE_BACKEND` | 已实现的规则适配器 | `iptables_restore` |
| `BYPASS_SET_BACKEND` | 已实现的绕过分类器 | `zone` |
| `MSS_CLAMP_ENABLE` | TCP MSS 钳制 | `1` |
| `BLOCK_QUIC` | 阻断 UDP/443 | `0` |

其他兼容字段见 [`conf/settings.ini`](conf/settings.ini)。

## CLI

```bash
/data/adb/flux/scripts/fluxctl status [--json]
/data/adb/flux/scripts/fluxctl start
/data/adb/flux/scripts/fluxctl stop
/data/adb/flux/scripts/fluxctl restart
/data/adb/flux/scripts/fluxctl reload
/data/adb/flux/scripts/fluxctl resync
/data/adb/flux/scripts/fluxctl diagnose
/data/adb/flux/scripts/fluxctl rules-preview
/data/adb/flux/scripts/fluxctl logs [file]
```

`status` 直接返回权威的 `fluxd` 状态，其中包括由 Rust 管理的 Sing-Box 运行状态。所有修改命令只通过
私有控制 socket 执行，不会回退到直接调用 shell 修改系统。

## 开发状态

构建、测试、特权 canary、Android 交叉编译、模块暂存和包一致性验证说明见
[`docs/development.md`](docs/development.md)。开发暂存目录不等于可发布产物；当前
`cargo xtask verify-package` 只检查临时 hybrid 包的一致性，即使通过也不能绕过 ADR-0011。发布前必须先
把验证清单切换为纯 Rust 运行时，拒绝 standalone `addrsyncd`、`jq`、旧运行时脚本与兼容包装器，再完成
不可变来源/哈希、SBOM、设备证据、固定工具链、完整校验和、可复现 provenance 与可信 attestation。

已交付的桥接渲染器只是 xtables 第一个非修改型切换：Rust 负责准备兼容字节，shell 仍负责 restore
执行、readback、回滚与内核修改。独立的规范 lowerer 已保留 schema-v1 转发入口身份，并描述完整的
schema-v2 本地 OUTPUT `O`/`P` 事务。crate-private 原生 owner 也已为独立准入的目标提供稳定 hook 修改、
精确的事务内策略路由、双族 readback/残留审计、回滚、恢复、清理和迁移租约。尚未完成的是生产目标准入、
listener/engine/canary 权威、Android 5.10/ARM64 评审资格以及 shell writer 切换，因此生产 driver 仍返回
`Unsupported`。nftables 与 TUN 继续推迟；eBPF 仍为可选能力，生产路径不会加载 `.ko`/KPM 模块。

## 免责声明

- 本项目仅供教育和研究使用，请勿用于非法用途。
- 透明代理和策略路由修改可能与 Android VPN/netd 策略冲突。
- 在依赖本模块前，请保留回滚路径并在受支持设备上完成测试。

## 鸣谢

- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [taamarin/box_for_magisk](https://github.com/taamarin/box_for_magisk)
- [CHIZI-0618/box4magisk](https://github.com/CHIZI-0618/box4magisk)
- [jqlang/jq](https://github.com/jqlang/jq)

## 许可证

[GPL-3.0](LICENSE)
