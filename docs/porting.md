# 移植到另一台机器 / 另一个学校

本项目的**协议层是通用的**（我们只是"指挥后台服务"，与有线/无线无关，
`wlanuserip` / `wlanusermac` / AC 地址都由服务自己在运行时探测，脚本里一个都没写死）。
但有几样东西**绑定本机或本校**，换环境必须重做。

---

## 一、必须重做的（换机器就要做）

| 项 | 为什么 | 怎么做 |
| --- | --- | --- |
| **凭据文件 `dial.secrets.json`** | 用 **Windows DPAPI** 加密，绑定「本机 + 本 Windows 账户」。拷过去解不开（这是故意的） | 在新机器上双击 `cmd\setup-dialer-credential.cmd`，输入**他自己的**账号口令 |
| **计划任务 `TianyicampusDialer`** | 任务动作里写的是**绝对路径**（`<仓库>\src\TianyicampusDialer.ps1`），换路径就失效 | 在新机器上双击 `cmd\install-dialer.cmd` |
| **官方客户端** | 我们指挥的是服务 `ESurfingSvr`，它由官方「天翼校园」客户端安装 | 先装客户端，并**用他自己的账号成功登录过一次** |

> 换句话说：**把文件夹拷过去 ≠ 能用**，必须在目标机上跑一遍 `install-dialer.cmd`。

---

## 二、可能要调判定参数的（换学校才要调）

环境判定在 `src\Guard.Env.psm1` 的 `Get-EnvironmentClassification`，输入来自
`config\guard.config.json`：

| 信号 | 配置项 | 默认值 | 说明 |
| --- | --- | --- | --- |
| S1 | `CampusCidr` | `100.64.0.0/10` | 电信 CGNAT 段，全国电信校园网都用它，一般不用改 |
| S2 | `CampusGateway` | `100.67.192.1` | **这是开发所在学校的网关，换学校几乎肯定要改** |
| S3 | `PortalHosts` + `ContentMarkers` | `175.12.104.*` / `124.232.225.*` / `*.189.cn`；`detect.html`/`wlanuserip`/`189.cn`/`auth.cgi` | 门户劫持特征；同省同系统一般通用 |

判定规则：

* **命中门户劫持（S3）→ 直接判 CAMPUS**（一票通过，不看总分）；
* 否则 **总分 ≥ 4 → CAMPUS**；**总分 0 → HOME**（不动作）；**1–3 分 → UNKNOWN**（保守不动）。

所以：**只要对方学校的门户还是天翼那套（会出现 `wlanuserip` / `auth.cgi` / `189.cn`），
即使 `CampusGateway` 不对也大概率能直接用**——因为未认证时 S3 必然命中。

如果 `cmd\status-dialer.cmd` 显示 `env=UNKNOWN`，说明既没劫持、分数也不够，按下面修：

1. 在校园网里执行 `ipconfig`，看他实际的默认网关；
2. 把 `config\guard.config.json` 的 `CampusGateway` 改成那个值；
3. 再跑一次 `cmd\status-dialer.cmd`，应当变成 `env=CAMPUS`。

---

## 三、无线（笔记本 WiFi）能不能用

**能，不需要改任何东西。** 理由：

* 网卡采集用的是 .NET `NetworkInterface`，`Wireless80211` 在支持列表里
  （有线和无线同时在线时优先有线）；
* 报文里只有 `<user>` 和 `<password>`，`wlanusermac` 由服务按**实际使用的网卡**自己取；
* 官方客户端本身也支持无线（它的日志里就有 `CheckWifi` 流程）。

---

## 四、移植清单（照着做）

```
1. 目标机装好官方天翼校园客户端，用他自己的账号登录成功过一次
2. 拷贝本项目文件夹到目标机（任意路径，避免含空格的路径以免 .cmd 麻烦）
3. 双击 cmd\install-dialer.cmd        ← 录入他自己的账号口令 + 注册任务（一次 UAC）
4. 双击 cmd\status-dialer.cmd         ← 确认 env=CAMPUS、凭据、服务、管道都正常
      若 env=UNKNOWN：按第二节改 CampusGateway
5. 双击 cmd\test-dialer-recovery.cmd  ← 验证掉线自愈（会主动断开一次）
6. 双击 cmd\test.cmd                  ← 单测（可选，应 82/82）
```

---

## 五、常见问题

| 现象 | 原因 / 处理 |
| --- | --- |
| `status` 里 `凭据: 缺失` | 还没录入。跑 `cmd\setup-dialer-credential.cmd` |
| `status` 里 `env=UNKNOWN` | 判定特征不全，按第二节改 `CampusGateway` |
| `status` 里 `管道空闲: False (busy)` | 官方客户端 GUI 正在运行并占着管道（单实例）。守护会**让位**给它，这是设计如此 |
| 拨号返回退出码 3 | 凭据缺失或解不开（换机器/换账户后 DPAPI 失效，需重新录入） |
| 拨号返回退出码 2 | 服务起不来（需要提权 → 确认用 `install-dialer.cmd` 装的任务）、或管道被占、或认证失败 |
| 官方客户端完全没装 | 本项目依赖它的后台服务，必须先装 |
| 对方学校**不是电信天翼**这套 | 本项目不适用（协议/服务都不同） |

---

## 六、不要做什么

* **不要把 `dial.secrets.json` 拷给别人** —— 那既是别人的机器解不开的密文，也等于交出你的账号；
* 不要把 `logs\`、`docs\evidence\`、`cwe-dec*` 打包发给别人 —— 前者含运行记录与本机标识，
  后者是把电信客户端 UI 解出来的明文（他人专有代码）。这些已在 `.gitignore` 中排除，
  但**手动打包 zip 时不受 `.gitignore` 保护**；
* 不要自己实现那层 `auth.cgi` 加密信封 —— `Algo-ID` 由服务端动态更换，
  协议也封在加密模块里（见 `docs\protocol-findings.md` 的说明）。直接指挥服务才是正路。