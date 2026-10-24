# 贡献指南

先读 [README.md](README.md)（怎么用）和 [docs/protocol-findings.md](docs/protocol-findings.md)（协议怎么来的、为什么这么实现）。
改代码前请先看下面的三条硬规矩，它们都是踩过坑才立起来的。

## 三条硬规矩

### 1. `.cmd` 文件必须是纯 ASCII

cmd.exe 按 **ANSI(GBK)** 解析批处理文件，`chcp 65001` 只影响控制台输出、**不影响解析**。
写入 UTF-8 中文会被误解码，一旦某个被吃掉的字节导致**引号不成对**，
cmd 就会吞掉后续行（包括提权逻辑），症状是**窗口一闪就退** —— 完全不像编码问题，极难排查。

```powershell
# 自查：非 ASCII 字节数应为 0
Get-ChildItem cmd -Filter *.cmd | ForEach-Object {
  $n = @((Get-Content $_.FullName -Encoding Byte) | Where-Object { $_ -gt 127 }).Count
  if ($n) { "NON-ASCII ($n): $($_.Name)" }
}
```

### 2. `.ps1` / `.psm1` 必须带 UTF-8 BOM

PowerShell 5.1 对**无 BOM** 的文件按 ANSI 解码。中文被误解码后，
行尾"悬挂的双字节首字节"会吃掉换行、把下一行并入注释，导致大括号失配、模块加载失败。

> 注意：不少编辑器/工具在保存时会**静默剥掉 BOM**，所以每次改完脚本都要复核一遍。

```powershell
# 自查：前三字节应是 239,187,191
Get-ChildItem src,tests,tools -Filter *.ps*1 | ForEach-Object {
  if (((Get-Content $_.FullName -Encoding Byte -TotalCount 3) -join ',') -ne '239,187,191') {
    "MISSING BOM: $($_.Name)"
  }
}
```

### 3. 绝不提交凭据

* 真实账号、口令、`dial.secrets.json`、抓包、日志、`%APPDATA%` 里的客户端配置 —— **一律不入库**；
* 需要账号口令的地方**不要写默认值**，让它从 `dial.secrets.json`（DPAPI）或命令行参数来；
* 提交前跑一次审计：

```powershell
git grep --cached -n -E '<你自己的账号>|<你自己的口令>'
```

`.gitignore` 已经排除了 `logs/`、`runtime/`、`dial.secrets.json`、`docs/evidence/`、`cwe-dec*`。

## 改完怎么验

```powershell
cmd\test.cmd                       # 单元测试，应全部通过
cmd\status-dialer.cmd              # 只读现场状态：环境判定 / 服务 / 管道 / 凭据 / 线上格式
```

涉及真实拨号的改动，用 `cmd\test-dialer-recovery.cmd` 验自愈能力
（它会**主动断开一次**网络，然后要求守护在无人工干预下自己恢复）。

## 关于协议层改动

* 线上格式是**实测**出来的：`UTF-16LE`、无分帧。改编码/分帧前请先用
  `cmd\probe-portal-wire.cmd` 重新测定，不要凭直觉改；
* 登录三步 **必须在同一条管道连接上依次发送**（`ClientStart → CheckEnv → PortalConnect`）；
  断开发 `PortalDisConnect` 之前也必须先在同一条连接上发过 `ClientStart`。
  这是服务端按连接维护状态机导致的，拆开就会静默失效；
* **不要**尝试自己实现 `auth.cgi` 那层加密信封 —— `Algo-ID` 由服务端动态更换，
  算法封在加密模块里。直接指挥服务才是正路。

## 报问题

* 功能问题：开 issue，附 `cmd\status-dialer.cmd` 的输出和 `logs\dialer-<日期>.log` 的相关片段
  （**先自行抹掉账号、MAC、内网 IP**）；
* 安全问题：不要开公开 issue，请私下联系维护者。

## 许可

提交贡献即表示同意以本仓库的 [MIT License](LICENSE) 授权。