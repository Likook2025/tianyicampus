# 天翼校园网自动登录守护（Tianyicampus Dialer）

Windows 上**绕开官方客户端 GUI**、全自动完成电信天翼校园网认证的守护程序。

不开窗口、不弹 UAC、不点鼠标，也不需要自己实现那套加密协议 —— 做法是**直接指挥官方后台服务**。

```
计划任务 TianyicampusDialer（登录 Windows 时触发 + 最高权限 → 免 UAC）
  └─ src\TianyicampusDialer.ps1 -Watch
       ├─ 环境判定：家庭网络直接不动作；校园网才干活
       ├─ 确保拨号服务 ESurfingSvr 在跑（会话靠它每 5 分钟的 keep.cgi 心跳续命）
       ├─ 官方客户端 GUI 在跑就让位给它（管道是单实例）
       └─ 同一条连接依次发：ClientStart → CheckEnv → PortalConnect
```

## 实测验收

| 验收项 | 结果 |
| --- | --- |
| 纯终端登录 | ✅ `portal connect start → account is → authUrl → record connected` |
| 守护常驻循环 | ✅ 单实例锁正常，按轮询间隔稳定轮转 |
| **掉线自愈** | ✅ 会话被强制踢掉后，守护在**无人工干预**下自己恢复（实测 85 秒） |

## 工作原理

真正干活的是 Windows 服务 **`ESurfingSvr`**（加密、`auth.cgi`、心跳全在它里面），
官方客户端 GUI 只是它的**命名管道客户端**。所以我们不去驱动 GUI，直接对服务说话：

| 项目 | 值 |
| --- | --- |
| 管道 | `\\.\pipe\ESurfingClientPipe`（**单实例**；**只放行提权进程**） |
| 线上格式 | **UTF-16LE 裸报文，无分帧**（4 编码 × 5 分帧共 20 种组合实测，只有它命中） |
| 报文 | `<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>命令</OpC><P>参数</P></M>` |
| 登录三步 | `ClientStart` → `CheckEnv` → `PortalConnect`，**必须走同一条连接** |
| 口令 | 服务端要**明文**（PAP），加密信封由服务端负责 —— 我们完全不碰 |

协议是怎么一步步查出来的、以及走过的弯路，见 **[docs/protocol-findings.md](docs/protocol-findings.md)**；
开发中修掉的真 bug 与踩过的坑，见 **[docs/dev-notes.md](docs/dev-notes.md)**。

## 安装（三步，只需一次）

```
1) 先在本机装好官方「天翼校园」客户端，并用你自己的账号成功登录过一次
   （我们要指挥的后台服务 ESurfingSvr 由它安装）

2) 双击  cmd\install-dialer.cmd
   · 若还没有凭据，它会先问你的【校园网账号 + 口令】
   · 口令用 Windows DPAPI 加密保存在 dial.secrets.json
     只有「本机 + 本 Windows 账户」能解开，不落明文、不进版本库
   · 然后注册计划任务（登录触发 + 最高权限，所以不弹 UAC）

3) 完事。以后每次登录 Windows 都会自动认证，无窗口、无点击、掉线自愈。
```

| 想做的事 | 双击 |
| --- | --- |
| 换账号 / 改口令 | `cmd\setup-dialer-credential.cmd` |
| 看当前状态（只读，不需要提权） | `cmd\status-dialer.cmd` |
| 立刻拨号一次 | `cmd\run-dialer-now.cmd` |
| 前台跑监控循环（排障用） | `cmd\run-dialer-watch.cmd` |
| 验证掉线自愈（会主动断开一次） | `cmd\test-dialer-recovery.cmd` |
| 跑单元测试 | `cmd\test.cmd` |
| 彻底卸载（只删本项目的计划任务） | `cmd\uninstall-dialer.cmd` |

> **给别的同学用**：每人账号口令不同，**复制文件夹后必须重新运行一次 `cmd\install-dialer.cmd`**
> —— 凭据与计划任务都绑定本机/本账户，不能拷贝。
> 有线与无线都支持，不需要改任何东西；换学校可能要调判定参数，见 **[docs/porting.md](docs/porting.md)**。

## 目录结构

```
config\guard.config.json        唯一可调参数文件
src\TianyicampusDialer.ps1      入口（-Once / -Watch / -Status / -Install / -Uninstall）
src\Guard.Dialer.psm1           终端拨号模块：命令表、XML 转义、UTF-16LE 编解码、
                                管道探测、凭据加载（DPAPI）、单连接三步登录编排
src\Guard.Env.psm1              网络环境判定（纯函数，可离线单测）
src\Guard.Client.psm1           客户端/服务定位与进程控制
src\Guard.Log.psm1              日志（按天落盘 + 过期清理）
src\Guard.Runtime.psm1          配置加载校验、单实例锁、路径解析
cmd\*.cmd                       .cmd 包装器（自带提权；**必须保持纯 ASCII**）
tools\                          一次性诊断与验证工具（见下）
tests\Guard.Tests.ps1           Pester 单测
logs\dialer-yyyyMMdd.log        运行日志（不进版本库）
dial.secrets.json               DPAPI 凭据（不进版本库）
```

## 环境判定规则

输入全部是纯数据，便于离线测试。四项信号加权：

| 信号 | 内容 | 权重 |
| --- | --- | --- |
| S1 | 有网卡 IPv4 属于 `CampusCidr`（默认 `100.64.0.0/10`，电信 CGNAT 段） | +2 |
| S2 | 默认网关等于 `CampusGateway` | +2 |
| S3 | HTTP 被校园门户劫持（跳门户主机 / 响应体含门户特征） | +3 |
| S4 | 可选门户探针 `EnablePortalDetectProbe`（默认关） | +3 |

结论：

* **命中 S3（劫持）或总分 ≥ 4 → CAMPUS**（才动作）；
* 总分 0 → **HOME**（不动作；家里路由器给的 `192.168.x.x` 就走这条）；
* 没有活动网关，或 1–3 分（特征不完整）→ **UNKNOWN**（保守不动作，日志会写清命中了哪些信号）。

认证判据：中性地址返回正常正文且**不含任何门户劫持特征**。
**只看 HTTP 200 不算数**（BAS 返回门户页也是 200）。

## 配置项（`config\guard.config.json`）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `ServiceName` | `ESurfingSvr` | 拨号服务名 |
| `ClientProcessName` | `ESurfingClient` | 用于判断官方 GUI 是否在占用管道 |
| `NeutralProbeUrl` | `http://www.msftconnecttest.com/connecttest.txt` | 中性探测地址（只读） |
| `NeutralProbeExpectedContent` | `Microsoft Connect Test` | 认证成功时该返回的正文 |
| `ProbeTimeoutSec` | 5 | 探测超时 |
| `PortalHosts` | `124.232.225.*` 等 | 判定门户劫持的目标主机 |
| `ContentMarkers` | `detect.html` 等 | 判定门户劫持的响应体特征 |
| `CampusCidr` | `100.64.0.0/10` | 校园网地址段 |
| `CampusGateway` | `100.67.192.1` | 校园网默认网关（**换学校改这里**） |
| `PollIntervalCampus` | 20 | 校园网未认证时的轮询间隔（秒） |
| `PollIntervalIdle` | 120 | 已认证/家庭网络时的轮询间隔（秒） |
| `OnceVerifyTimeoutSec` | 60 | 拨号后等待认证的秒数 |
| `LogRetentionDays` / `LogLevel` | 14 / `Info` | 日志保留与级别 |
| `DryRun` | `false` | 只判定与记录，不拨号 |
| `TaskName` | `TianyicampusDialer` | 计划任务名 |

非法取值会回退到默认值并在日志里写告警，不会让守护挂掉。

## 排障

先看 `cmd\status-dialer.cmd`（只读），再用 `logs\dialer-<日期>.log` 对照：

| 现象 | 原因 / 处理 |
| --- | --- |
| `凭据: 缺失` | 还没录入。跑 `cmd\setup-dialer-credential.cmd` |
| `env=UNKNOWN` | 判定特征不全。在校园网里 `ipconfig` 看真实网关，改 `CampusGateway` |
| `管道空闲: False (busy)` | 官方客户端 GUI 在跑并占着管道（单实例）。守护会**让位**给它，这是设计如此 |
| 退出码 2 | 服务起不来（需要提权 → 用 `install-dialer.cmd` 装任务）、或管道被占、或认证失败 |
| 退出码 3 | 凭据缺失或解不开（换机器/换账户后 DPAPI 会失效，需重新录入） |
| 完全没有官方客户端 | 本项目依赖它的后台服务，必须先装 |

## 移植到别的机器 / 别的学校

见 **[docs/porting.md](docs/porting.md)**（含无线能不能用、要改哪些判定参数、常见问题）。

## 贡献

见 **[CONTRIBUTING.md](CONTRIBUTING.md)**。三条硬规矩：`.cmd` 必须纯 ASCII、
`.ps1`/`.psm1` 必须带 UTF-8 BOM、绝不提交凭据。

## 说明与边界

* 本项目**不读取、不上传**你的账号口令之外的任何东西；客户端配置只读，不改官方客户端、
  不改注册表；对系统的唯一改动就是那个计划任务，`cmd\uninstall-dialer.cmd` 可一键移除。
* 依赖官方客户端已经登录成功过一次（服务需要它下发/缓存必要的运行参数）。
* 不同学校/省份的门户可能是别的系统，此时本项目不适用。
* 请遵守你所在学校/运营商的使用规定；本项目只是把"你本来要手点一次"的登录自动化。

## 许可

[MIT](LICENSE)