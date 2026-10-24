# 天翼校园客户端 · 后台服务管道协议（已破解并实测打通）

> 最后更新：2026-10-24 · 接手本项目的 agent
> 相关工具：`tools\Probe-PortalPipeWire.ps1`、`tools\Try-PortalLogin.ps1`、`src\Guard.Dialer.psm1`

---

## 一、结论速览

**可以完全跳开 GUI**：后台服务 `ESurfingSvr` 才是真正干活的（加密、`auth.cgi`、`keep.cgi` 心跳），
GUI 只是命名管道客户端。协议已解出，且**终端已经被服务端接受**（实测）。

```
管道：\\.\pipe\ESurfingClientPipe
  单实例 —— GUI 运行时会独占，必须先退出 GUI；
  ACL 只放行提权进程 —— 必须提权运行（GUI 本身是 requireAdministrator）。

线上格式：UTF-16LE 裸报文，无分帧   ← 实测确认，见下
报文：<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>命令</OpC><P>参数</P></M>
```

登录三步：

| 顺序 | OpC | P | 说明 |
| --- | --- | --- | --- |
| 1 | `ClientStart` | *(空)* | 服务回 `server is running, client state is 31`，并开始自检 |
| 2 | `CheckEnv` | *(空)* | 触发环境探测（detect.html → index.cgi → 拿 wlanuserip/mscgip/ticket） |
| 3 | `PortalConnect` | `<user>账号</user><password>口令</password>` | **真正的登录**，口令要**明文** |

⚠️ **这三步必须在同一条管道连接上依次发出。** 每条报文各开一条连接时，
服务只处理前两条，`PortalConnect` 会被彻底无视（日志里连 `portal connect start` 都不出现）。
GUI 就是一条长连接跑完整个会话 —— 服务按连接维护状态机。

断开：`PortalDisConnect`，P = `<src>来源标识</src>`。

⚠️ 端点必须先"注册"：**在新连接上单独发 `PortalDisConnect` 是无效的**。
实测（`logs\recovery-20261024-174621.txt`）：单发之后会话照旧在线，服务日志只反复出现
`DisConnect For <src>` + `disconnect return 2 / 1 / -3`；改成像客户端那样在**同一条连接**上
先发 `ClientStart` 再发 `PortalDisConnect`，会话立刻断开。
这与登录三步必须同连接是同一条规律：**服务按连接维护状态机**。

---

## 二、线上格式是怎么确定的（实测，非推测）

`tools\Probe-PortalPipeWire.ps1` 一次跑完 **4 种编码 × 5 种分帧 = 20 个组合**，
每个组合在**同一条连接上**连发 `ClientStart` + `CheckEnv`，然后核对服务日志里有没有出现我们的报文。

结果：**只有 `UTF16LE / Raw` 命中**，其余 19 种全部被服务端无视。

服务端原样记录（`20261024_svrinfo.log`）：

```
2026-10-24 13:33:35.832 - <M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>ClientStart</OpC><P></P></M>
2026-10-24 13:33:38.329 - server is running, client state is 31
```

旁证：`plugin\ServerModule.dll`（GUI 侧负责 `PostServerMsg` 的组件）里，
报文模板 `<M><OpS>%s</OpS><OpT>%s</OpT><OpC>%s</OpC><P>%s</P></M>` 存在于**宽字符串表**，
该模块的字符串表整体都是 UTF-16（ASCII 表 0 命中）。所以"UTF-16LE"不是巧合。

### 走错过的路（别再试）

* 用 **UTF-8** 发 —— 服务端完全不处理（这是最初误判"管道走不通"的根因）；
* 非提权进程连管道 —— `ERROR_ACCESS_DENIED`（提权后立刻 `连接=True`）；
* 每条消息新开一条连接 —— GUI 实际是**一条长连接**连发多条，旧脚本的写法也掩盖了真正的问题。

---

## 三、完整命令表（来自解密出的 `view\js\dialMgr.js`）

```js
var CLIENT_START            = 'ClientStart';
var CLIENT_START_COMPLETE   = 'ClientStartComplete';
var SERVER_STATUS_RESP      = 'ServerStatusResp';
var CHECK_ENV               = 'CheckEnv';
var CHECK_ENV_RESP          = 'CheckEnvResp';
var GET_NETINFO_RESP        = 'GetNetInfoResp';
var PORTAL_CONNECT          = 'PortalConnect';
var PORTAL_CONNECT_RESP     = 'PortalConnectResp';
var PORTAL_DISCONNECT       = 'PortalDisConnect';
var PORTAL_DISCONNECT_RESP  = 'PortalDisconnectResp';
var APP_ERR                 = 'AppErr';
var CHECK_WIFI_RESP         = 'CheckWifiResp';
var NET_STATE_MESSAGE_RESP  = 'NetStateMessageResp';
var NET_STATE_MESSAGE_RESP_EX = 'NetStateMessageRespEx';
var TICKET_RESP             = 'TicketResp';
var SET_VALUE               = 'SetValue';
var GET_VALUE               = 'GetValue';
var FUN_CFG                 = 'FunCfg';
var LOG_TRACE               = 'Log';
var LOG_CHECK_WIFI_POST     = 'LogCheckWifiPost';
var TERMINAL_REQUEST        = 'GetTerminalData';
var TERMINAL_RESP           = 'SetTerminalData';
var TERMINAL_TERM_REQUEST   = 'TerminalTermSend';
var TERMINAL_TERM_RESP      = 'TerminalTermReturn';
var CHECK_SYSTEM_TIME       = 'CheckSystemTime';
var DATA_SUBMIT             = 'DataSubmit';
var DISASTER_URL            = 'DisasterUrl';

// 数据源/数据目标固定为 Portal/Portal
DialMgr.prototype.postPortalMsg = function (opCode, param, cbFun) {
    $cwe.plugin('servermodule').call('PostServerMsg', 'Portal', 'Portal', opCode, param, cbFun);
};
DialMgr.prototype.start      = function ()                 { this.postPortalMsg(CLIENT_START, ''); };
DialMgr.prototype.checkNet   = function ()                 { this.postPortalMsg(CHECK_ENV, ''); };
DialMgr.prototype.connect    = function (userName, password) {
    this.postPortalMsg(PORTAL_CONNECT,
        '<user>' + userName + '</user><password>' + password + '</password>');
};
DialMgr.prototype.disconnect = function (tip, cbFun) {
    this.postPortalMsg(PORTAL_DISCONNECT, '<src>' + tip + '</src>', cbFun);
};
```

口令是**明文 PAP**（与服务端下发的 `<auth><type>cdc-http-pap</type><default>yes</default></auth>` 一致），
加密信封由**服务端**在发 `auth.cgi` 时套上 —— 我们的工具完全不碰那层加密。

---

## 四、凭据存在哪（重要，之前一直找错地方）

```
C:\Users\<用户>\AppData\Roaming\ChinatelecomJSPortal\Config\config.xml
```

```xml
<Account>
  <Portal Val="13800138000（示例）"/>
  <PortalPassword Val="（此处原为本机实测的 Base64 密文，已移除）" />   <!-- Base64，16 字节 = DES 两个分组 -->
  <Save Val="1"/>
</Account>
```

* 安装目录下的 `Config\config.xml` **只是**日志级别等运行参数，**不含凭据**；
* 凭据键名（来自 `plugin\InfoCenterModule.dll` 与 `ServerModule.dll` 的字符串）：
  `Account.Portal`、`Account.PortalPassword`、`Account.Save`、`PortalAccount` 等；
* `InfoCenterModule.dll` 内含 `DES_Crypto` 类，并读取 `\\.\PhysicalDrive%d`
  —— 说明 DES 密钥很可能由**硬件指纹**派生，所以密文换台机器解不开。

---

## 五、破解 Web UI 的方法（可复现）

客户端 53 个 HTML/JS 都是 `!#CWERD#` 加密容器，由 `cwe.dll` 运行时解密。

分析结论（`tools\Analyze-CweContainer.py`）：

1. 熵 ≈ 7.99，密文长度 = 明文长度（**无分组填充**）；
2. 周期扫描 1..1024 **无任何尖峰**（命中率恒为 1/256 随机基线）→ 不是重复密钥 XOR；
3. **不同目录下的两个 `dialMgr.js` 密文起始逐字节相同** → **密钥流是全局固定序列、不带 per-file IV**。

于是偏移 `i` 处有多个观测 `c_j = K_i ⊕ p_j`，以 JS 源码字节分布为先验做极大似然即可恢复 `K`；
再用解出的文本重建先验（EM）迭代收敛。`tools\Recover-CweProtocol.py` 实测 EM 5 轮后
可信度（最优−次优）中位数 9.91，偏移 0..12000 区间明文完全可读。

### 还能更准（未使用的外部捷径）

`view\js\mootools-core-1.4-full.js` 是公开开源库，明文 151394 字节。
拿到它的原始文件就能 XOR 出 15 万字节精确密钥流，**全部文件 100% 解出**。
本机与全盘都没有明文副本；本沙箱内 HTTPS 不通、`web_fetch` 拒收 JS 类型、`web_search` 无密钥，
所以这条路没走。需要"完美明文"时让用户手动下载一次即可。

---

## 六、已实测的行为（做方案时必须考虑）

| 行为 | 证据 |
| --- | --- |
| **从托盘退出客户端会主动发 `PortalDisConnect`，网络随之断开** | 13:27:06 客户端退出 → 服务日志立刻出现 `PortalDisConnect <src>1</src>` → `record not connect` → 网络掉线 |
| 客户端**非正常退出**（崩溃/被杀）不发该报文 | 13:06:41 只有 `GetOverlappedResult failed 109` + `client disconnect 1`，服务继续保活 |
| GUI 不在时服务**仍会保活**已建立的会话 | 13:06:41 断开后 13:08:51 `keep.cgi ret 1, code 0` 仍成功 |
| 服务只在**新管道连接的第一条报文**上记 Info 日志 | `ClientStart`/`CheckEnv`/`PortalDisConnect` 被记录，`PortalConnect` 从未被记录 |
| 改客户端日志级别（`KernelLog Level=Debug`）**抓不到报文** | `svrdebug.log` 在整个登录过程中始终 0 字节；服务确实重读了配置并新建了日志文件，但没有 Debug 输出 |
| 服务不重启也会重读 `config.xml` | 收到 `ClientStart` 时重读（日志里能看到它重读 Build 号、并新建当天日志文件） |

---

## 七、已确认（原先的三个疑问都有了答案）

1. **`PortalConnect` 的口令形态 = 明文。**
   用配置文件里那段 Base64 密文发时，服务虽然受理了报文
   （日志出现 `portal connect start` / `account is` / `authUrl is`），
   但**在 `authUrl` 之后仅 10 ms 就报错** —— 根本来不及向 `175.12.104.1` 发 HTTP，
   说明是**本地**就把口令拒了。换成明文口令后立刻成功：
   `record connected`，网络恢复。
2. **服务不校验连接方进程身份。** 我们的报文被正常受理并回话
   （`server is running, client state is 31`），并非只认 `ESurfingClient.exe`。
3. **三步必须走同一条连接**（这是最后一个卡点）：
   每条报文新开连接时，`ClientStart`/`CheckEnv` 会被处理，但 `PortalConnect`
   会被**彻底无视**（日志里连 `portal connect start` 都不出现）；
   改成同一条连接后立刻成功。服务按连接维护状态机，GUI 就是一条长连接跑完整个会话。

### 端到端成功记录（2026-10-24 17:06）

```
17:06:03.961 - client disconnect 1
17:06:04.622 - portal connect start
17:06:04.638 - NetStateChange curState 33, oldState 0,newState 1,code 0,subCode
17:06:04.653 - account is 13800138000（示例）
17:06:04.653 - authUrl is :http://175.12.104.1:10001/auth.cgi
17:06:04.766 - NetStateChange curState 1, oldState 1,newState 2,code 1,subCode auth
17:06:04.782 - record connected
```

判定行：`portal connect start=True  account is=True  record connected=True`，网络回到 `Authenticated`。
完整报告：`logs\login-trial-20261024-170530.txt`。

### 守护自愈能力验证（2026-10-24 17:48，最终验收）

做法：`tools\Test-DialerRecovery.ps1` **只发一条断开报文**（用一个提权进程把会话踢掉），
之后**不拨号、不干预**，只观察网络何时恢复——恢复必须由**正在运行的守护**完成。

```
17:48:00.833 [守护] 环境判定: CAMPUS ... auth=Unknown          ← 守护发现掉线
17:48:08.793 [守护] 终端拨号已发送（UTF16LE/Raw）: Ok=True 步骤=3
17:48:11.235 [守护] 拨号后认证校验: Authenticated               ← 恢复

17:48:08.874 [服务] portal connect start
17:48:08.876 [服务] account is 13800138000（示例）
17:48:08.884 [服务] authUrl is :http://175.12.104.1:10001/auth.cgi
17:48:08.967 [服务] record connected
```

脚本计时：**85 秒内自行恢复**（守护已认证时每 120 秒判定一轮，属正常节奏）。
报告：`logs\recovery-20261024-174621.txt`。

### 仍未做（不影响使用）

* 服务主动推出的其它异步报文（`NetStateMessageResp`、`TicketResp`、`AppErr` 等）的完整含义；
* `keep.cgi` 心跳是否需要我们参与（当前由服务自己维持，实测无需干预）。

---

## 八、建议架构（终端方案）

```
计划任务（登录触发、最高权限 → 无 UAC）
  └─ PowerShell 脚本（无窗口）
       ├─ 环境判定（复用 src\Guard.Env.psm1）：不是校园网就退出
       ├─ 确保 ESurfingSvr 已启动（DEMAND_START，需提权）
       ├─ 确认 GUI 未运行（否则管道单实例被占）
       ├─ 连接 \\.\pipe\ESurfingClientPipe（UTF-16LE 裸报文）
       ├─ ClientStart → CheckEnv → PortalConnect(<user>,<password>)
       ├─ 校验 http://www.msftconnecttest.com/connecttest.txt 正文
       └─ 失败重试；成功后每分钟探活
```

优点：**不开 GUI、不弹窗、不点鼠标、不碰加密**。
风险点：管道单实例（必须保证 GUI 不在跑）；凭据形态待定。

---

## 九、仓库里新增的工具

| 文件 | 用途 |
| --- | --- |
| `src\Guard.Dialer.psm1` | 终端拨号模块（命令表、转义、UTF-16LE 编解码、凭据加载含 DPAPI、登录编排） |
| `tools\Analyze-CweContainer.py` | 识别 `!#CWERD#` 容器、测周期/熵、用 crib 求密钥流 |
| `tools\Recover-CweProtocol.py` | EM 迭代恢复全局密钥流并批量解密 UI 代码 |
| `tools\Probe-PortalPipeWire.ps1` + `cmd\probe-portal-wire.cmd` | **线上格式测定（就是它确定了 UTF-16LE/Raw）** |
| `tools\Try-PortalLogin.ps1` + `cmd\try-portal-login.cmd` | 端到端纯终端登录验证（读凭据文件 → 三步报文 → 判成功） |
| `tools\Test-DialerRecovery.ps1` + `cmd\test-dialer-recovery.cmd` | 掉线自愈验证（只断开、不拨号；恢复必须由守护自己完成） |

---

## 十、编码陷阱（踩过，务必记住）

* 本仓库所有 `.ps1`/`.psm1` **必须带 UTF-8 BOM**。PowerShell 5.1 对无 BOM 文件按 ANSI(GBK) 解码，
  中文字节被误解码后，行尾"悬挂的双字节首字节"会吃掉换行、把下一行并入注释，
  导致大括号失配、模块加载失败。`src\Guard.Client.psm1` 历史上就漏了 BOM。
* **编辑工具会剥掉 BOM**：每次编辑 `.ps1`/`.psm1` 后都要把 BOM 补回去（作为最后一次编辑）。
* 客户端自己的文件是 **GBK**（安装目录）与 **UTF-8**（`%APPDATA%\ChinatelecomJSPortal`）混用，
  读日志时注意 `Get-Content -Encoding`。