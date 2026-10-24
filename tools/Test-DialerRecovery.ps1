<#
    Test-DialerRecovery.ps1
    端到端验证：正在运行的守护能不能自己把掉线的校园网救回来。

    做法
    ----
    本脚本**只负责踢一脚**：向后台服务发一条 PortalDisConnect 把会话断开，
    然后**什么都不做**，只观察网络何时恢复。

    ★ 恢复必须由正在运行的守护（-Watch）完成，本脚本绝不自己去拨号 ——
      否则测的就是"脚本能不能登录"，而不是"守护能不能自愈"，那没有意义。

    前提
    ----
      * 守护正在 -Watch 模式运行（cmd\run-dialer-watch.cmd 的窗口还开着）；
      * 官方客户端 GUI 没在运行（管道单实例必须是空闲的）；
      * 提权运行（管道的 ACL 只放行提权进程）。

    观察窗口默认 300 秒：守护在"已认证"状态下每 PollIntervalIdle（默认 120 秒）
    才判定一次，所以最坏情况要等约 2 分钟才轮到下一轮。

    报告写到 logs\recovery-<stamp>.txt（自包含，断网也不丢）。
#>
[CmdletBinding()]
param(
    [string]$PipeName         = 'ESurfingClientPipe',
    [string]$ProbeUrl         = 'http://www.msftconnecttest.com/connecttest.txt',
    [string]$ExpectedContent  = 'Microsoft Connect Test',
    [int]$ObserveSec          = 300,
    [int]$ConnectTimeoutMs    = 3000,
    [int]$DropConfirmSec      = 15
)

$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$logDir   = Join-Path $repoRoot 'logs'
if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$reportPath = Join-Path $logDir ('recovery-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')

$script:lines = New-Object System.Collections.Generic.List[string]
function Say { param([string]$T)
    $l = ('[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss.fff'), $T)
    $script:lines.Add($l); Write-Host $l
    try { [System.IO.File]::WriteAllLines($reportPath, $script:lines, (New-Object System.Text.UTF8Encoding($true))) } catch { }
}
function SayRaw { param([string]$T)
    $script:lines.Add($T)
    try { [System.IO.File]::WriteAllLines($reportPath, $script:lines, (New-Object System.Text.UTF8Encoding($true))) } catch { }
}

Import-Module (Join-Path $repoRoot 'src\Guard.Dialer.psm1') -Force -DisableNameChecking

function Test-Online {
    try {
        $r = Invoke-WebRequest -Uri $ProbeUrl -TimeoutSec 8 -UseBasicParsing
        if ($r.Content -match [regex]::Escape($ExpectedContent)) { return 'Authenticated' }
        return 'Hijacked'
    } catch { return 'Offline' }
}

Say '================================================================'
Say '守护自愈能力验证（只断开、不拨号；恢复必须由守护完成）'
Say ('报告: ' + $reportPath)
Say ('已提权: ' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$svc = Get-Service ESurfingSvr -ErrorAction SilentlyContinue
Say ('服务 ESurfingSvr: ' + $(if ($svc) { $svc.Status } else { '未找到' }))

# 管道必须空闲（提权后能连上 = 没有 GUI 占着）
try {
    $probePipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $probePipe.Connect($ConnectTimeoutMs); $probePipe.Dispose()
    Say '管道空闲 ✓（官方客户端未运行）'
} catch {
    Say ('管道不可用：' + $_.Exception.Message.Split([char]10)[0])
    Say '=> 官方客户端 GUI 可能正在运行并占用管道。请先从托盘退出客户端再重跑。'
    Say '提前结束。'
    return
}

$before = Test-Online
Say ('断开前网络: ' + $before)
if ($before -ne 'Authenticated') {
    Say '当前本来就不是已认证状态，没有可测的"掉线→恢复"。提前结束。'
    return
}

# ── 踢一脚：PortalDisConnect ────────────────────────────────────────────────
Say ''
Say '--- 步骤 1：发送 PortalDisConnect（唯一动作，之后本脚本不再拨号）---'
$r = Send-GuardPortalDisconnect -PipeName $PipeName -Source 'recovery-test'
Say ("  连接={0} 已发={1} {2}" -f $r.Ok, $r.Sent, $r.Error)

$dropped = $false
$deadline = (Get-Date).AddSeconds($DropConfirmSec)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if ((Test-Online) -ne 'Authenticated') { $dropped = $true; break }
}
Say ('  会话是否已断开: ' + $dropped)

if (-not $dropped) {
    Say ''
    Say '--- 步骤 1b：单发没断掉，改成像客户端那样在同一条连接上先 ClientStart 再断开 ---'
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect($ConnectTimeoutMs)
        foreach ($body in @(
            (New-PortalPipeMessage -OpCode (Get-PortalCommand).ClientStart -Param ''),
            (New-PortalPipeMessage -OpCode (Get-PortalCommand).PortalDisConnect -Param (New-PortalDisconnectParam -Source 'recovery-test'))
        )) {
            $bytes = Get-PortalFramingBytes -Message $body
            $pipe.Write($bytes, 0, $bytes.Length); $pipe.Flush()
            Start-Sleep -Milliseconds 1200
        }
        Say '  已在同一条连接上发送 ClientStart + PortalDisConnect'
    } catch {
        Say ('  失败: ' + $_.Exception.Message.Split([char]10)[0])
    } finally { if ($pipe) { try { $pipe.Dispose() } catch { } } }

    $deadline = (Get-Date).AddSeconds($DropConfirmSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        if ((Test-Online) -ne 'Authenticated') { $dropped = $true; break }
    }
    Say ('  会话是否已断开: ' + $dropped)
}

if (-not $dropped) {
    Say '=> 没能把会话断开，测试无法进行（这不影响你的网络）。提前结束。'
    return
}

# ── 只观察，不干预 ──────────────────────────────────────────────────────────
Say ''
Say '--- 步骤 2：现在只观察（本脚本不会拨号）---'
Say ('  网络已断开，开始计时。守护应该在自己的下一轮里发现并拨号。')
Say ('  最多等 {0} 秒。' -f $ObserveSec)

$start = Get-Date
$recovered = $false
$elapsed = 0
while (((Get-Date) - $start).TotalSeconds -lt $ObserveSec) {
    Start-Sleep -Seconds 3
    $state = Test-Online
    $elapsed = [int]((Get-Date) - $start).TotalSeconds
    if ($state -eq 'Authenticated') { $recovered = $true; break }
    if ($elapsed % 15 -lt 3) { Say ('    已等 {0} 秒，当前: {1}' -f $elapsed, $state) }
}

Say ''
Say '================================================================'
if ($recovered) {
    Say ('*** 成功：守护在 {0} 秒内把网络自己救回来了（全程无人干预）***' -f $elapsed)
    Say '=> 守护自愈能力得到实证。'
} else {
    Say ('*** 失败：等了 {0} 秒网络仍未恢复 ***' -f $ObserveSec)
    Say '=> 请检查：守护窗口是否还开着？它的日志 logs\dialer-<日期>.log 里有没有新的"终端拨号已发送"？'
    Say '   恢复网络：双击 cmd\run-dialer-now.cmd（或打开官方客户端点一次登录）。'
}
Say ('报告: ' + $reportPath)