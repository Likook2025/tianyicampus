<#
    Try-PortalLogin.ps1
    用终端直接命令后台服务完成认证 —— 端到端验证（已被授权的一次断网窗口）。

    已知（都已实测确认，见 docs\protocol-findings.md）：
      * 管道：\\.\pipe\ESurfingClientPipe，单实例，只放行提权进程
      * 线上格式：UTF-16LE 裸报文，无分帧
      * 报文：<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>命令</OpC><P>参数</P></M>
      * 三步：ClientStart → CheckEnv → PortalConnect
      * 凭据：%APPDATA%\ChinatelecomJSPortal\Config\config.xml
              <Account><Portal Val="账号"/><PortalPassword Val="Base64 密文"/></Account>

    ★ 本版最重要的一处修正：
      上一版**每条报文都新开一条连接**，而 GUI 是**一条长连接连发整个会话**。
      服务按连接维护状态机 —— 结果就是 ClientStart/CheckEnv 被处理，
      但单独一条连接上的 PortalConnect 被彻底无视（日志里连 portal connect start 都没有）。
      本版改成：**每个场景用同一条连接跑完三步**。

    判定成功的信号（按可靠性排序）：
      1) 日志出现 record connected           —— 认证真的成功
      2) 日志出现 portal connect start        —— 服务开始处理登录（口令对错都会出现）
      3) 日志出现 account is <账号>           —— 同上，紧随其后

    用法：提权运行 —— cmd\try-portal-login.cmd
#>
[CmdletBinding()]
param(
    [string]$PipeName   = 'ESurfingClientPipe',
    [string]$ConfigPath = "$env:APPDATA\ChinatelecomJSPortal\Config\config.xml",
    [string]$SecretPath,
    [int]$ConnectTimeoutMs = 3000,
    [int]$DrainSliceMs     = 300,
    [int]$AfterConnectMs   = 20000,
    [int]$WaitForPipeSec   = 150
)

$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
# 注意：$PSScriptRoot 在 param() 默认值里是空的（PS 5.1 行为），只能在脚本体里算。
if ([string]::IsNullOrWhiteSpace($SecretPath)) {
    $SecretPath = Join-Path $repoRoot 'dial.secrets.json'
}
$logDir   = Join-Path $repoRoot 'logs'
if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$reportPath = Join-Path $logDir ('login-trial-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')

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
function Get-SvrLogFile {
    $d='D:\tools\Chinatelecom_JSPortal\log'
    if(-not (Test-Path -LiteralPath $d)){ return $null }
    Get-ChildItem -LiteralPath $d -Filter '*svrinfo.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { $_.FullName }
}
function Read-LogFrom { param([string]$Path,[long]$Offset)
    if(-not $Path){ return '' }
    try {
        $fs=[System.IO.File]::Open($Path,'Open','Read','ReadWrite')
        try { [void]$fs.Seek($Offset,'Begin')
              $sr=New-Object System.IO.StreamReader($fs,[System.Text.Encoding]::GetEncoding(936))
              $t=$sr.ReadToEnd(); $sr.Close(); return $t } finally { $fs.Close() }
    } catch { return '' }
}
function Test-NetOnline {
    try { $r=Invoke-WebRequest 'http://www.msftconnecttest.com/connecttest.txt' -TimeoutSec 6 -UseBasicParsing
          if($r.Content -match 'Microsoft Connect Test'){ return 'Authenticated' } else { return 'Hijacked' } }
    catch { return 'Offline' }
}
function New-Body { param([string]$OpCode,[string]$Param='')
    return ('<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>{0}</OpC><P>{1}</P></M>' -f $OpCode,$Param)
}

# ★ 同一个场景共用一个连接：ClientStart → CheckEnv → PortalConnect
function Invoke-LoginScenario {
    param([string]$Label,[string]$User,[string]$Password,[string]$LogFile)
    Say ''
    Say ('=== 场景：{0} ===' -f $Label)
    $mark = 0; if($LogFile){ $mark = (Get-Item -LiteralPath $LogFile).Length }

    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.',$PipeName,[System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect($ConnectTimeoutMs)
        Say '  已连上管道（下面三步都走这一条连接）'
    } catch {
        Say ('  连接失败: ' + $_.Exception.Message.Split([char]10)[0]); return
    }

    try {
        $seq = @(
            [pscustomobject]@{ Op='ClientStart';    Param='';                                            Wait=900  },
            [pscustomobject]@{ Op='CheckEnv';       Param='';                                            Wait=1500 },
            [pscustomobject]@{ Op='PortalConnect';  Param=('<user>{0}</user><password>{1}</password>' -f $User,$Password); Wait=$AfterConnectMs }
        )
        foreach ($s in $seq) {
            $body  = New-Body -OpCode $s.Op -Param $s.Param
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($body)
            try { $pipe.Write($bytes,0,$bytes.Length); $pipe.Flush() }
            catch { Say ('  {0} 写入失败: {1}' -f $s.Op, $_.Exception.Message.Split([char]10)[0]); break }

            $reply = New-Object System.Collections.Generic.List[byte]
            $deadline=(Get-Date).AddMilliseconds($s.Wait)
            while((Get-Date) -lt $deadline){
                if(-not $pipe.IsConnected){ break }
                try { $pipe.ReadTimeout=$DrainSliceMs; $buf=New-Object byte[] 32768; $n=$pipe.Read($buf,0,$buf.Length) } catch { continue }
                if($n -gt 0){ for($i=0;$i -lt $n;$i++){ $reply.Add($buf[$i]) } }
            }
            $txt = if($reply.Count -gt 0){ [System.Text.Encoding]::Unicode.GetString($reply.ToArray()).Trim([char]0) } else { '' }
            Say ('  已发 {0,-14} {1,4} 字节  回包={2}' -f $s.Op, $bytes.Length, $(if($txt){'有'}else{'无'}))
            if($txt){ SayRaw ('      回包: ' + ($txt -replace "`r?`n",' ')) }
        }
    } finally { try { $pipe.Dispose() } catch { } }

    Start-Sleep -Milliseconds 800
    $delta = Read-LogFrom -Path $LogFile -Offset $mark
    $connectStart = ($delta -match 'portal connect start')
    $accountSeen  = ($delta -match 'account is')
    $connected    = ($delta -match 'record connected')
    Say ('  判定: portal connect start={0}  account is={1}  record connected={2}' -f $connectStart,$accountSeen,$connected)
    Say ('  网络: ' + (Test-NetOnline))
    SayRaw '  服务日志增量:'
    foreach($l in ($delta -split "`r?`n")){ if($l.Trim()){ SayRaw ('    | ' + $l) } }
    return [pscustomobject]@{ Label=$Label; Accepted=$connectStart; Connected=$connected; Delta=$delta }
}

# ── 主流程 ──────────────────────────────────────────────────────────────────
Say '================================================================'
Say '天翼校园 · 纯终端登录端到端验证（单连接版）'
Say ('报告: ' + $reportPath)
Say ('已提权: ' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$svc=Get-Service ESurfingSvr -ErrorAction SilentlyContinue
Say ('服务: ' + $(if($svc){$svc.Status}else{'未找到'}))
Say ('启动时网络: ' + (Test-NetOnline))

$logFile=Get-SvrLogFile
Say ('服务日志: ' + $logFile)

Say ''
Say '--- 步骤 1：读取凭据文件 ---'
$user=''; $storedPwd=''
if(-not (Test-Path -LiteralPath $ConfigPath)){ Say ('找不到凭据文件: ' + $ConfigPath) }
else {
    try {
        $xml=[xml](Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8)
        $acct=$xml.eclient_config.Account
        $user=[string]$acct.Portal.Val
        $storedPwd=[string]$acct.PortalPassword.Val
        Say ('  账号 = ' + $user + '   存储口令 = ' + $storedPwd + '（' + $storedPwd.Length + ' 字符）')
    } catch { Say ('  解析失败: ' + $_.Exception.Message) }
}
Say ''
Say '--- 步骤 1b：读取 DPAPI 保护的明文凭据 ---'
$plainPwd = ''
if (Test-Path -LiteralPath $SecretPath) {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Guard.Dialer.psm1') -Force -DisableNameChecking
    $cred = Get-GuardDialCredential -SecretPath $SecretPath
    if ($cred.Ok) {
        if (-not $user) { $user = $cred.User }
        $plainPwd = $cred.Password
        Say ('  已取到明文口令（来源=' + $cred.Source + '，长度 ' + $plainPwd.Length + '，磁盘上无明文）')
    } else { Say ('  读取失败: ' + $cred.Error) }
} else { Say ('  没有凭据文件: ' + $SecretPath) }

if(-not $user){ Say '拿不到账号，终止。'; return }

Say ''
Say '============================================================'
Say '  请现在从托盘退出天翼客户端：右键托盘图标 -> 退出'
Say ('  本脚本最多等 {0} 秒；退出后会自动继续。' -f $WaitForPipeSec)
Say '============================================================'
$free=$false; $waited=0
while($waited -lt $WaitForPipeSec){
    try { $p=New-Object System.IO.Pipes.NamedPipeClientStream('.',$PipeName,[System.IO.Pipes.PipeDirection]::InOut)
          $p.Connect(1200); $p.Dispose(); $free=$true; break } catch { }
    Start-Sleep -Seconds 2; $waited+=2
    if($waited % 15 -eq 0){ Say ('  仍在等待客户端退出…… 已等 {0} 秒' -f $waited) }
}
if(-not $free){ Say ('等待超时（{0} 秒）：客户端仍占用管道。' -f $WaitForPipeSec); Say '终止。'; return }
Say ('管道空闲，开始（等待了 {0} 秒）。' -f $waited)

# 场景 A：优先用 DPAPI 里的**明文**口令。
# 实测：用配置文件里那段存储态密文时，服务在 authUrl 之后 10ms 就本地报错
# （根本来不及发 HTTP），说明它要的是明文。
$rA = $null; $rB = $null
if ($plainPwd) {
    $rA = Invoke-LoginScenario -Label 'PortalConnect，口令=明文（DPAPI 凭据）' -User $user -Password $plainPwd -LogFile $logFile
} else {
    $rA = Invoke-LoginScenario -Label 'PortalConnect，口令=配置文件原文（没有明文可用）' -User $user -Password $storedPwd -LogFile $logFile
}

# 场景 B：A 没成功时，再试配置文件里那段存储态密文，用于对照
if (-not $rA.Connected) {
    $rB = Invoke-LoginScenario -Label 'PortalConnect，口令=配置文件里的存储态密文' -User $user -Password $storedPwd -LogFile $logFile
}

Say ''
Say '================================================================'
if($rA.Connected -or ($rB -and $rB.Connected)){
    Say '*** 成功：纯终端完成认证，全程没有 GUI、没有点击 ***'
} elseif($rA.Accepted -or ($rB -and $rB.Accepted)){
    Say '*** 报文已被服务受理（出现了 portal connect start），但认证没成功 ***'
    Say '=> 服务确实在处理我们的登录，但这一轮口令没通过。看上面各场景的判定行，'
    Say '   对照 authUrl 之后是否立刻报错（本地拒）还是走了 http（服务端拒）。'
} else {
    Say '*** 两个场景都没被受理（日志里没有 portal connect start）***'
    Say '=> PortalConnect 仍未被服务处理。下一步应比对 GUI 侧 ServerModule.dll 的写入路径，'
    Say '   或考虑服务在 PortalConnect 前还要求别的握手（例如共享内存注册）。'
}
Say ('报告: ' + $reportPath)