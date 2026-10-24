# 开发记录：修掉的真 bug 与踩过的坑

这份文档记录**为什么代码长成现在这样**。每一条都是实测暴露出来的，不是推测。

---

## 一、修掉的 5 个真 bug

### 1. `Get-ClientLoginState -Since` 声明成不可空类型

```
[Error] 单次执行异常: Cannot process argument transformation on parameter 'Since'.
        Cannot convert null to type "System.DateTime".
```

调用方在"查不到客户端进程启动时间"时会传 `$null`，而参数声明是 `[datetime]` —— 直接抛异常，
把整个守护拖垮，而不是降级成 `Unknown`。已改为 `[Nullable[datetime]]`，并加了回归用例。

### 2. 一个源文件缺 UTF-8 BOM

`src\Guard.Client.psm1` 曾是全仓库唯一**没有 BOM** 的文件，却含 777 个非 ASCII 字节。
PowerShell 5.1 对无 BOM 文件按 ANSI(GBK) 解码，中文字节被误解码后，
**行尾"悬挂的双字节首字节"会吃掉换行**，把下一行并入注释 → 大括号失配、模块加载失败。
已补 BOM，并复核全部脚本。

### 3. `-Watch` 从来没真正跑起来过

`Enter-GuardInstance` 返回的是 **FileStream**（拿不到时返回 `$null`），
而代码写成 `if (-not $lock.Acquired)` —— FileStream 没有 `.Acquired` 属性，表达式**恒为真**，
于是每次启动都判定"已有实例在运行"并退出。守护一次都没真正运行过。

这个 bug 之所以难发现，是因为它**看起来像成功**：机器重启后网络是通的。
但那是**校园网会话跨重启存活**（BAS 会话绑 MAC/IP，不绑机器开机时长）造成的假阳性 ——
服务日志里一条登录记录都没有，服务甚至处于 `Stopped`。

> 教训：**"症状消失"永远不能替代"产生了做事的证据"**。验收要看正面产物（守护自己的日志、服务端的登录记录）。

### 4. 重启后拨号服务没被拉起

"确保服务在跑"原本排在"已认证就返回"**之后**。但会话是靠服务里的 `KeepPluseThread`
每 5 分钟发 `keep.cgi` 续命的 —— 服务停了心跳就断，BAS 空闲超时后会踢人。
重启实测：服务是 `Stopped`（`DEMAND_START`，没人拉起它），而会话还没过期、网络看着是通的；
不补这一步，几分钟后网络会自己断。

已把"确保服务在跑"移到认证判断**之前**：只要在校园网就必须让服务跑起来。

### 5. `.cmd` 里写了 UTF-8 中文 → 窗口一闪就退

cmd.exe 按 **ANSI(GBK)** 解析批处理文件，`chcp 65001` 只影响控制台输出、**不影响解析**。
写入 UTF-8 中文被误解码后丢了一个引号，**未闭合的引号让 cmd 吞掉了后续行**
（包括 `if defined GUARD_ELEVATED goto payload` 提权逻辑），脚本整个错乱。

症状完全不像编码问题，所以现在所有 `.cmd` 都是纯 ASCII（见 [CONTRIBUTING.md](../CONTRIBUTING.md)）。

### 6. 服务还没就绪就发 `PortalConnect`，被静默拒掉

用户重启实测暴露的（2026-10-24 19:51）：重启后服务是 `Stopped`、**由守护把它拉起来**，
守护随即在约 7 秒后发了 `PortalConnect` —— 但服务这时还没准备好：

```
19:51:19.396 <M>…ClientStart…</M>        ← 守护
19:51:20.936 <M>…CheckEnv…</M>           ← 守护
19:51:26.791 portal connect start        ← 守护
19:51:26.791 m_pAutoZsm is NULL          ← 【加密算法模块还没加载】
19:51:26.791 authUrl is :                ← 认证地址为空
19:51:26.791 request 6 return err 12006,retry
19:51:29.165 load AutoZSM begin/end      ← 2.4 秒后才加载完成
19:51:31.324 waiting for authentication. ← 服务此刻才真正就绪
```

关键点：**服务被拒后不会自己重试**，那一次登录就这么没了。
（用户随后手动打开客户端能连上，正是因为那时服务已经就绪。）

**真正的判据是 `authUrl` 有没有值，而不是算法模块。** 修好之后再跑一次开机测试，
同样出现 `m_pAutoZsm is NULL`，但这次 `authUrl` 已经有值，连接直接成功：

```
20:7:41.856 <M>…ClientStart…</M>         ← 守护（注意这次先等了 8 秒才发）
20:7:43.410 <M>…CheckEnv…</M>            ← 守护
20:7:51.487 portal connect start         ← 守护
20:7:51.487 m_pAutoZsm is NULL           ← 同样是 NULL，但……
20:7:51.487 authUrl is :http://175.12.104.1:10001/auth.cgi   ← 这次有值 → 成功
20:7:52.41  load AutoZSM begin/end       ← 算法模块两次都是在连接过程中才懒加载
20:7:52.553 portal connect start         ← 服务随后自己又补发一次，完成认证
```

也就是说 `AutoZSM` 是**误导项**（两次都在连接过程中加载）；真正的阻塞是
**服务还没抓到服务端下发的配置（`auth-url`）**——而抓配置要等它跑完一轮环境探测
（`detect.html → 302 → index.cgi`）。

这也解释了为什么早先几次测试都成功 —— 那时服务已经跑了很久、配置早已抓到；
**失败只发生在"服务刚被拉起"的场景，也就是每次开机。**

修法：

* 若服务是**我们启动的**，先等 `ServiceStartSettleSec`（默认 8 秒）让它完成环境探测、抓到配置；
* `CheckEnv → PortalConnect` 的间隔从 1.5 秒放宽到 3 秒；
* **外层加重试**（`DialAttempts` 默认 3 次、间隔 `DialRetryGapSec` 默认 12 秒）作为保险：
  冷启动万一第一次仍赶不上，第二次一定能赶上；热启动仍然一次成功。每次重试都换新连接并自带
  `ClientStart`（服务按连接维护状态机，这一点不能省）。

实测结果（2026-10-24 20:07 开机）：守护 20:07:32 启动 → 20:07:33 拉起服务 →
20:07:50 发报文 → **20:07:53 认证成功，第 1 次尝试就成功**（开机后约 42 秒，全程无人干预）。

---

## 二、协议层的三个卡点

这三个不是代码 bug，而是**目标系统的事实**，但代价最大：

| 卡点 | 结论 |
| --- | --- |
| 线上格式 | **UTF-16LE 裸报文，无分帧**。20 种"编码 × 分帧"组合实测只有它命中；UTF-8 会被彻底无视（最初误判"管道走不通"的根因） |
| 权限 | 管道只放行**提权**进程（官方 GUI 本身是 `requireAdministrator`）；非提权连接报 `ERROR_ACCESS_DENIED` |
| 连接模型 | 登录三步**必须走同一条连接**；连"断开"都要先在同一条连接上发过 `ClientStart` 才生效 |

最后一条是最贵的：每条消息各开一条连接时，`ClientStart`/`CheckEnv` 会被正常处理，
`PortalConnect` 却被**彻底无视**——日志里连 `portal connect start` 都不出现，很容易误判成"口令不对"。

---

## 三、被证明无效的路线（别再走）

* **改客户端日志级别到 Debug 抓报文**：服务确实重读了配置并新建了调试日志文件，
  但整个过程 `svrdebug.log` 始终 0 字节 —— 服务不把收到的报文写进调试日志。
* **用 UTF-8 发报文**：服务端完全不处理。定位线上格式必须实测，不能凭直觉。
* **从配置文件反推明文口令**：客户端存的是 DES 密文（`InfoCenterModule.dll` 的 `DES_Crypto`，
  密钥疑似由 `\\.\PhysicalDrive` 硬件指纹派生）。最终是**直接问使用者**拿到的明文 ——
  绕了一大圈，最便宜的路径其实最先就该走。
* **自己实现 `auth.cgi` 那层加密**：`Algo-ID` 由服务端动态下发更换，算法封在加密模块里，
  静态分析挖不出来。直接指挥服务才是正路。

---

## 四、可复现的实验工具

协议不是猜出来的，全部结论都有可以重跑的脚本：

| 工具 | 用途 |
| --- | --- |
| `tools\Probe-PortalPipeWire.ps1` + `cmd\probe-portal-wire.cmd` | 测定线上格式（就是它确定了 UTF-16LE/Raw） |
| `tools\Try-PortalLogin.ps1` + `cmd\try-portal-login.cmd` | 端到端登录验证 |
| `tools\Test-DialerRecovery.ps1` + `cmd\test-dialer-recovery.cmd` | 掉线自愈验证（只断开、不拨号） |
| `tools\Analyze-CweContainer.py` | 分析客户端 `!#CWERD#` 加密容器（熵/周期/已知明文攻击可行性） |
| `tools\Recover-CweProtocol.py` | 恢复全局密钥流并批量解密客户端 Web UI 代码（协议命令表就是这么拿到的） |

> 最后两个工具处理的是**官方客户端自己的文件**。它们的价值在于说明协议来源，
> 请只在你自己已安装的客户端上、出于互操作性研究的目的使用。