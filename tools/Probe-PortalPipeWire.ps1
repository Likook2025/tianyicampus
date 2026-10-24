<#
    Probe-PortalPipeWire.ps1
    测定 ESurfingSvr 命名管道的"线上格式"：编码 × 分帧。

    为什么需要它
    ------------
    上一版试验（Test-PortalPipeTrial.ps1）证明：
      * 提权后能连上管道（四种分帧全部 连接=True）；
      * 服务也确实注意到了我们的连/断（日志里每 3 秒一条 client disconnect 1）；
      * 但服务**从未记录过我们发的任何一条 <M>**，也没回话。
    而 GUI 发同样的 ClientStart 是会被记进 svrinfo.log 的。

    已知：plugin\ServerModule.dll 里的报文模板是**宽字符串**
      <M><OpS>%s</OpS><OpT>%s</OpT><OpC>%s</OpC><P>%s</P></M>
    所以线上到底跑 UTF-8 还是 UTF-16 必须实测。另有两个待验差异：
      * GUI 是**一条长连接**连发多条报文，而不是每条消息新开连接；
      * 可能需要长度前缀等分帧。

    本脚本对每个 编码×分帧 组合：
      1. 开一条连接；
      2. 在**同一条连接上**依次发 ClientStart、CheckEnv；
      3. 全程读回复；
      4. 核对服务日志新增内容里有没有出现我们发的 <M>；
      5. 命中即停止。

    全部结论写入 logs\pipe-wire-<stamp>.txt（自包含，断网也不丢）。

    用法（必须提权，用 cmd\probe-portal-wire.cmd）：
      powershell -File tools\Probe-PortalPipeWire.ps1
#>
[CmdletBinding()]
param(
    [string]$PipeName = 'ESurfingClientPipe',
    [int]$ConnectTimeoutMs = 3000,
    [int]$AfterWriteMs     = 1500,   # 每条报文后给服务留的处理时间
    [int]$ReadSliceMs      = 400
)

$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$logDir   = Join-Path $repoRoot 'logs'
if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$reportPath = Join-Path $logDir ('pipe-wire-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')

$script:lines = New-Object System.Collections.Generic.List[string]
function Say {
    param([string]$Text)
    $line = ('[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss.fff'), $Text)
    $script:lines.Add($line); Write-Host $line
    try { [System.IO.File]::WriteAllLines($reportPath, $script:lines, (New-Object System.Text.UTF8Encoding($true))) } catch { }
}
function SayRaw {
    param([string]$Text)
    $script:lines.Add($Text)
    try { [System.IO.File]::WriteAllLines($reportPath, $script:lines, (New-Object System.Text.UTF8Encoding($true))) } catch { }
}

# ── 服务日志读取 ────────────────────────────────────────────────────────────
function Get-SvrLogFile {
    $d = 'D:\tools\Chinatelecom_JSPortal\log'
    if (-not (Test-Path -LiteralPath $d)) { return $null }
    Get-ChildItem -LiteralPath $d -Filter '*svrinfo.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { $_.FullName }
}
function Read-LogFrom {
    param([string]$Path, [long]$Offset)
    if (-not $Path) { return '' }
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            [void]$fs.Seek($Offset, 'Begin')
            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::GetEncoding(936))
            $txt = $sr.ReadToEnd(); $sr.Close(); return $txt
        } finally { $fs.Close() }
    } catch { return '' }
}

# ── 构造字节 ────────────────────────────────────────────────────────────────
function New-Body { param([string]$OpCode, [string]$Param = '')
    return ('<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>{0}</OpC><P>{1}</P></M>' -f $OpCode, $Param)
}
function Get-Payload {
    param([string]$Text, [string]$EncodingName, [string]$Framing)
    switch ($EncodingName) {
        'UTF8'     { $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text) }
        'UTF16LE'  { $bytes = [System.Text.Encoding]::Unicode.GetBytes($Text) }
        'UTF16BE'  { $bytes = [System.Text.Encoding]::BigEndianUnicode.GetBytes($Text) }
        'ANSI936'  { $bytes = [System.Text.Encoding]::GetEncoding(936).GetBytes($Text) }
        default    { $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text) }
    }
    switch ($Framing) {
        'Null'    { $bytes = $bytes + [byte]0 }
        'CrLf'    { $bytes = $bytes + [byte]13 + [byte]10 }
        'Lf'      { $bytes = $bytes + [byte]10 }
        'Len32LE' {
            $len = [BitConverter]::GetBytes([int]$bytes.Length)   # 4 字节小端长度前缀
            $bytes = $len + $bytes
        }
    }
    return ,$bytes
}

# ── 主流程 ──────────────────────────────────────────────────────────────────
Say '================================================================'
Say '天翼校园 · 后台服务管道「线上格式」测定'
Say ('报告: ' + $reportPath)
Say ('已提权: ' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$svc = Get-Service ESurfingSvr -ErrorAction SilentlyContinue
Say ('服务: ' + $(if ($svc) { $svc.Status } else { '未找到' }))

$logFile = Get-SvrLogFile
Say ('服务日志: ' + $logFile)
$logOffset = 0
if ($logFile) { $logOffset = (Get-Item -LiteralPath $logFile).Length }
Say ('日志起始偏移: ' + $logOffset)

# 先确认管道空闲（GUI 必须已退出）
try {
    $probe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $probe.Connect($ConnectTimeoutMs); $probe.Dispose()
    Say '管道空闲，可以开始。'
} catch {
    Say ('管道不可用（GUI 可能还在运行，请先从托盘退出客户端）: ' + $_.Exception.Message.Split([char]10)[0])
    Say '提前结束。'
    return
}

$encodings = @('UTF8', 'UTF16LE', 'UTF16BE', 'ANSI936')
$framings  = @('Raw', 'Null', 'CrLf', 'Lf', 'Len32LE')
$win = $null

foreach ($enc in $encodings) {
    foreach ($fr in $framings) {
        $tag = "$enc/$fr"
        $before = 0
        if ($logFile) { $before = (Get-Item -LiteralPath $logFile).Length }

        $pipe = $null
        $connOk = $false
        try {
            $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
            $pipe.Connect($ConnectTimeoutMs); $connOk = $true
        } catch {
            Say ("  {0,-16} 连接失败: {1}" -f $tag, $_.Exception.Message.Split([char]10)[0])
            continue
        }

        $replies = New-Object System.Collections.Generic.List[string]
        try {
            foreach ($body in @((New-Body 'ClientStart'), (New-Body 'CheckEnv'))) {
                $bytes = Get-Payload -Text $body -EncodingName $enc -Framing $fr
                $pipe.Write($bytes, 0, $bytes.Length); $pipe.Flush()
                $deadline = (Get-Date).AddMilliseconds($AfterWriteMs)
                while ((Get-Date) -lt $deadline) {
                    if (-not $pipe.IsConnected) { break }
                    try { $pipe.ReadTimeout = $ReadSliceMs; $buf = New-Object byte[] 8192; $n = $pipe.Read($buf, 0, $buf.Length) }
                    catch { continue }
                    if ($n -gt 0) { $replies.Add([System.Text.Encoding]::UTF8.GetString($buf, 0, $n)) }
                }
            }
        } catch {
            Say ("  {0,-16} 写失败: {1}" -f $tag, $_.Exception.Message.Split([char]10)[0])
        } finally { try { $pipe.Dispose() } catch { } }

        Start-Sleep -Milliseconds 500
        $delta = Read-LogFrom -Path $logFile -Offset $before
        $gotOurs = ($delta -match '<M>' -and $delta -match 'ClientStart')
        $replyLen = ($replies | Measure-Object -Property Length -Sum).Sum

        Say ("  {0,-16} 连接={1} 回复字节={2} 服务记录我们的报文={3}" -f $tag, $connOk, $replyLen, $gotOurs)
        if ($replyLen -gt 0) { SayRaw ('      回复: ' + (($replies -join ' | ') -replace "`r?`n", ' ')) }
        if ($gotOurs) {
            SayRaw '      服务日志增量:'
            foreach ($l in ($delta -split "`r?`n")) { if ($l.Trim()) { SayRaw ('        | ' + $l) } }
            $win = $tag
            break
        }
    }
    if ($win) { break }
}

Say ''
if ($win) {
    Say ("*** 命中！线上格式 = $win ***")
    Say '接下来：用该格式发 ClientStart → CheckEnv → PortalConnect 就能完成认证。'
} else {
    Say '*** 全部 20 种组合都没被服务记录 ***'
    Say '含义：问题不在编码/分帧，而很可能在于——'
    Say '  (a) 服务会校验连接方进程身份（只认 ESurfingClient.exe）；或'
    Say '  (b) 需要先完成某种握手（例如共享内存注册）才会开始收报文。'
    Say '下一步建议：抓 GUI 进程内存（找 PostServerMsg 附近的缓冲）或直接比对'
    Say 'GUI 侧 ServerModule.dll 的写入路径。'
}
Say '================================================================'
Say ('报告: ' + $reportPath)