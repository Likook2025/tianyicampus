<#
    TianyicampusDialer.ps1
    天翼校园网「无 GUI」自动登录守护。

    与旧方案的区别
    --------------
      旧：拉起官方客户端 GUI → 模拟点击「登录」按钮（窗口、UAC、点击时机都是坑）；
      新：**直接向后台服务 ESurfingSvr 的命名管道发三条明文报文**完成认证，
          全程不开窗口、不弹 UAC、不点鼠标、不碰那层加密。

    协议与全部实测依据见 docs\protocol-findings.md。要点：
      * 管道 \\.\pipe\ESurfingClientPipe：单实例、只放行提权进程；
      * 线上格式：UTF-16LE 裸报文，无分帧；
      * 三步 ClientStart → CheckEnv → PortalConnect，**必须走同一条连接**；
      * 凭据：dial.secrets.json（DPAPI，仅本机本用户可解）。

    参数
    ----
      -Once        判定并拨号一次（默认）
      -Watch       常驻循环（计划任务用）
      -Status      只读状态，不改动任何东西
      -Install     注册「登录时触发 + 最高权限」的计划任务（因此不需要 UAC）
      -Uninstall   移除计划任务
      -DryRun      只判定与记录，不拨号
      -SecretPath  凭据文件（默认 <repo>\dial.secrets.json）
      -TaskName    计划任务名（默认 TianyicampusDialer）

    退出码：0 正常/已认证 · 1 判定异常或无活动网关 · 2 校园网下拨号未成功 · 3 凭据缺失
#>
[CmdletBinding()]
param(
    [switch]$Once,
    [switch]$Watch,
    [switch]$Status,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$DryRun,
    [switch]$Quiet,
    [string]$ConfigPath,
    [string]$SecretPath,
    [string]$TaskName,
    [int]$MaxIterations = 0
)

$ErrorActionPreference = 'Continue'
$srcDirectory = $PSScriptRoot

Import-Module (Join-Path $srcDirectory 'Guard.Runtime.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Log.psm1')     -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Env.psm1')     -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Client.psm1')  -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Dialer.psm1')  -Force -DisableNameChecking

$dialerVersion = '1.0.0'
$script:ScriptPath = Join-Path $srcDirectory 'TianyicampusDialer.ps1'

$repoRoot = Get-GuardRepoRoot -ModuleRoot $srcDirectory
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $repoRoot 'config\guard.config.json' }
if ([string]::IsNullOrWhiteSpace($SecretPath)) { $SecretPath = Join-Path $repoRoot 'dial.secrets.json' }

$configResult = Import-GuardConfig -Path $ConfigPath
$config       = $configResult.Values
if ($DryRun) { $config['DryRun'] = $true }

# 任务名优先级：命令行 -TaskName > 配置 TaskName > 内置默认
$dialTaskName = if (-not [string]::IsNullOrWhiteSpace($TaskName)) { $TaskName }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$config['TaskName'])) { [string]$config['TaskName'] }
                else { 'TianyicampusDialer' }

$logDirectory = Get-GuardLogDir -RepoRoot $repoRoot
Initialize-GuardLog -Directory $logDirectory -RetentionDays $config['LogRetentionDays'] `
    -Level $config['LogLevel'] -Prefix 'dialer' -NoConsole:([bool]$Quiet) | Out-Null

trap {
    try {
        Write-GuardLog -Level Error -Message "未捕获异常: $($_.Exception.Message)" -Data @{
            type = $_.Exception.GetType().FullName
            at   = ($_.InvocationInfo.PositionMessage -replace "`r?`n", ' ')
        }
    } catch { }
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# 环境与认证
# ─────────────────────────────────────────────────────────────────────────────

function Get-DialEnvPicture {
    $snapshot = Get-NetworkSnapshot

    $probe = $null
    if ($snapshot.HasGateway) {
        $probe = Invoke-NeutralProbe -Url $config['NeutralProbeUrl'] -TimeoutSec $config['ProbeTimeoutSec']
    }
    $portalProbe = $null
    if ($config['EnablePortalDetectProbe'] -and $snapshot.HasGateway) {
        $portalProbe = Invoke-NeutralProbe -Url $config['PortalDetectUrl'] -TimeoutSec $config['ProbeTimeoutSec']
    }

    $classification = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $probe `
        -PortalProbeResult $portalProbe -Config $config -ForceEnv 'none'

    $authState = 'Unknown'
    if ($snapshot.HasGateway) {
        $authState = Get-AuthState -ProbeResult $probe -PortalHosts $config['PortalHosts'] `
            -ContentMarkers $config['ContentMarkers'] -ExpectedContent $config['NeutralProbeExpectedContent']
    }

    $networkText = '无活动网卡'
    if ($null -ne $snapshot.Primary) {
        $networkText = "$($snapshot.Primary.Name) $($snapshot.Primary.IPv4) GW=$($snapshot.Primary.Gateway)"
    }

    return [pscustomobject]@{
        Snapshot    = $snapshot
        Probe       = $probe
        AuthState   = $authState
        Env         = $classification.Env
        Reason      = $classification.Reason
        Signals     = $classification.Signals
        NetworkText = $networkText
    }
}

function Get-DialAuthState {
    $p = Invoke-NeutralProbe -Url $config['NeutralProbeUrl'] -TimeoutSec $config['ProbeTimeoutSec']
    return (Get-AuthState -ProbeResult $p -PortalHosts $config['PortalHosts'] `
        -ContentMarkers $config['ContentMarkers'] -ExpectedContent $config['NeutralProbeExpectedContent'])
}

function Wait-DialAuthenticated {
    param([int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $last = 'Unknown'
    while ((Get-Date) -lt $deadline) {
        $last = Get-DialAuthState
        if ($last -eq 'Authenticated') { return $last }
        Start-Sleep -Seconds 2
    }
    return $last
}

# ─────────────────────────────────────────────────────────────────────────────
# 一次完整判定 + 拨号
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-DialOnce {
    $picture = Get-DialEnvPicture

    Write-GuardLog -Level Info -Message "环境判定: $($picture.Env) ($($picture.Reason))" -Data @{
        auth    = $picture.AuthState
        signals = ($picture.Signals -join '; ')
        network = $picture.NetworkText
        probe   = (Get-ProbeSummary -ProbeResult $picture.Probe)
    }

    if ($picture.Env -eq 'HOME') {
        Write-GuardLog -Level Info -Message '家庭网络环境：不做任何动作'
        return [pscustomobject]@{ Env = 'HOME'; AuthState = $picture.AuthState; ExitCode = 0; Dialed = $false }
    }
    if ($picture.Env -ne 'CAMPUS') {
        Write-GuardLog -Level Warn -Message "环境既非校园网也非家庭（$($picture.Env)），保守不动作"
        return [pscustomobject]@{ Env = $picture.Env; AuthState = $picture.AuthState; ExitCode = 1; Dialed = $false }
    }
    if ($config['DryRun']) {
        Write-GuardLog -Level Info -Message 'DryRun: 只判定与记录（不会启动服务，也不会拨号）'
        return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = $picture.AuthState; ExitCode = 0; Dialed = $false }
    }

    # ★ 只要在校园网，就先把拨号服务确保起来 —— **不依赖是否已认证**。
    #   理由（实测教训）：会话是靠服务里的 KeepPluseThread 每 5 分钟发 keep.cgi 续命的；
    #   服务停了心跳就没了，BAS 会在空闲超时后把会话踢掉。
    #   2026-10-24 17:23 重启后实测：服务是 Stopped（DEMAND_START，没人拉起它），
    #   而当时会话还没过期、网络看着是通的 —— 不补这一步，几分钟后网络会自己断。
    $svcState = Get-CampusServiceState -ServiceName $config['ServiceName']
    if ($svcState -ne 'Running') {
        try {
            Start-Service -Name $config['ServiceName'] -ErrorAction Stop
            Write-GuardLog -Level Info -Message "已启动拨号服务 $($config['ServiceName'])（原状态 $svcState），它负责 keep.cgi 续命心跳"
            # ★ 刚启动的服务需要先做环境探测并加载加密算法模块，否则发 PortalConnect 会被拒。
            #   实测（2026-10-24 19:51，重启后）：
            #     19:51:26.791 portal connect start
            #     19:51:26.791 m_pAutoZsm is NULL      ← 算法模块还没加载
            #     19:51:26.791 authUrl is :            ← 认证地址为空
            #     19:51:26.791 request 6 return err 12006,retry   ← 服务返回 12006 后放弃，不会自己重试
            #     19:51:29.165 load AutoZSM begin/end  ← 2.4 秒后才加载完成
            #   所以这里先给它一点加载时间；真正的保险是下面的重试（冷启动第一次赶不上，
            #   第二次一定能赶上；热启动仍然一次成功）。
            $settle = [int]$config['ServiceStartSettleSec']
            if ($settle -gt 0) {
                Write-GuardLog -Level Info -Message "等待 $settle 秒让服务完成环境探测与算法模块加载"
                Start-Sleep -Seconds $settle
            }
        } catch {
            Write-GuardLog -Level Error -Message "拨号服务 $($config['ServiceName']) 未运行且启动失败（需要管理员权限，请确认已用 -Install 注册提权计划任务）: $($_.Exception.Message)"
            return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = $picture.AuthState; ExitCode = 2; Dialed = $false }
        }
    }

    if ($picture.AuthState -eq 'Authenticated') {
        Write-GuardLog -Level Info -Message '认证已在线且拨号服务在跑（心跳有人续），无需拨号'
        return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = 'Authenticated'; ExitCode = 0; Dialed = $false }
    }

    $cred = Get-GuardDialCredential -SecretPath $SecretPath
    if (-not $cred.Ok) {
        Write-GuardLog -Level Error -Message "拿不到拨号凭据，无法自动登录: $($cred.Error)" -Data @{ secret = $SecretPath }
        return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = $picture.AuthState; ExitCode = 3; Dialed = $false }
    }

    # 管道是单实例：谁先占谁用。
    # ★ 以**管道是否可用**为权威判据 —— 进程枚举在某些受限上下文里不可靠
    #   （实测：-Status 报 clientGui=False 的同时管道是 busy，因为提权的 GUI 枚举不到）。
    #   GUI 进程只用来决定日志措辞，不用来决定是否拨号。
    $pipe = Test-GuardPipeAvailable -ConnectTimeoutMs 2000
    if (-not $pipe.Free) {
        $guiRunning = Test-CampusClientRunning -ProcessName $config['ClientProcessName']
        if ($guiRunning) {
            Write-GuardLog -Level Warn -Message '官方客户端 GUI 正在运行并占用管道，本次让位给 GUI'
        } else {
            Write-GuardLog -Level Warn -Message "管道被占用（$($pipe.Reason)）但未枚举到 GUI 进程，本次跳过"
        }
        $state = Wait-DialAuthenticated -TimeoutSec 30
        $code = if ($state -eq 'Authenticated') { 0 } else { 2 }
        return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = $state; ExitCode = $code; Dialed = $false }
    }

    $wire = Get-PortalWireFormat
    $maxAttempts = [int]$config['DialAttempts']
    if ($maxAttempts -lt 1) { $maxAttempts = 1 }
    $retryGap    = [int]$config['DialRetryGapSec']
    if ($retryGap -lt 1) { $retryGap = 1 }

    # ★ 重试是关键：服务"冷启动"时（刚被我们拉起）算法模块还没加载完，
    #   第一次 PortalConnect 会被它以 err 12006 拒掉，而它**不会自己重试**；
    #   换一条新连接再来一次就好（每次尝试都必须自带 ClientStart —— 服务按连接维护状态机）。
    $state = $picture.AuthState
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $result = Invoke-GuardPortalLogin -User $cred.User -Password $cred.Password
        Write-GuardLog -Level Info -Message ("终端拨号已发送（{0}/{1}）第 {2}/{3} 次: Ok={4} 步骤={5}" -f `
            $wire.Encoding, $wire.Framing, $attempt, $maxAttempts, $result.Ok, $result.Steps.Count) -Data @{
            user    = $cred.User
            source  = $cred.Source
            error   = $result.Error
            attempt = $attempt
            steps   = (($result.Steps | ForEach-Object { '{0}:{1}B' -f $_.OpCode, $_.Sent }) -join ' ')
        }

        if (-not $result.Ok) {
            if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds $retryGap; continue }
            return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = $state; ExitCode = 2; Dialed = $true }
        }

        $state = Wait-DialAuthenticated -TimeoutSec $config['OnceVerifyTimeoutSec']
        if ($state -eq 'Authenticated') {
            Write-GuardLog -Level Info -Message "拨号后认证校验: Authenticated（第 $attempt 次尝试成功）"
            return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = 'Authenticated'; ExitCode = 0; Dialed = $true }
        }

        if ($attempt -lt $maxAttempts) {
            Write-GuardLog -Level Warn -Message ("第 {0}/{1} 次拨号未成功（校验={2}），{3} 秒后换一条连接重试" -f $attempt, $maxAttempts, $state, $retryGap)
            Start-Sleep -Seconds $retryGap
        }
    }

    Write-GuardLog -Level Warn -Message ("已重试 {0} 次仍未认证成功（最后校验={1}）" -f $maxAttempts, $state)
    return [pscustomobject]@{ Env = 'CAMPUS'; AuthState = $state; ExitCode = 2; Dialed = $true }
}

# ─────────────────────────────────────────────────────────────────────────────
# 计划任务（登录触发 + 最高权限 → 不需要 UAC）
# ─────────────────────────────────────────────────────────────────────────────

function Install-DialTask {
    if (-not (Test-GuardElevated)) {
        Write-GuardLog -Level Error -Message '注册计划任务需要管理员权限：任务必须以最高权限运行，否则无法启动 LocalSystem 的拨号服务'
        return 2
    }
    $argument = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Watch' -f $script:ScriptPath
    $user = Get-GuardCurrentUser
    $repeatMinutes = 30
    $repeatFrom = (Get-Date).AddMinutes(1)

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
                    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                    -MultipleInstances IgnoreNew
    $tLogon    = New-ScheduledTaskTrigger -AtLogOn -User $user

    # 重复触发器有两种写法，按顺序试 —— 因为**不同系统的 Task Scheduler 接受范围不同**：
    #   A) 不写 Duration      → 视为"无限重复"（推荐，兼容性最好）
    #   B) Duration=3650 天   → 备选
    # 曾经用 [TimeSpan]::MaxValue，cmdlet 自己不报错，但注册时被拒：
    #   "The task XML contains a value which is incorrectly formatted or out of range.
    #    (12,42):Duration:P99999999DT23H59M59S"
    # 那次静默回退成了"只有登录触发"的老任务 —— 所以这里**每一步都回读校验**，不再默默降级。
    $variants = @(
        [pscustomobject]@{ Name = '无 Duration（无限重复）'; Duration = $null },
        [pscustomobject]@{ Name = 'Duration=3650 天';        Duration = (New-TimeSpan -Days 3650) }
    )

    $lastError = ''
    foreach ($v in $variants) {
        try {
            if ($null -eq $v.Duration) {
                $tRepeat = New-ScheduledTaskTrigger -Once -At $repeatFrom `
                    -RepetitionInterval (New-TimeSpan -Minutes $repeatMinutes)
            } else {
                $tRepeat = New-ScheduledTaskTrigger -Once -At $repeatFrom `
                    -RepetitionInterval (New-TimeSpan -Minutes $repeatMinutes) `
                    -RepetitionDuration $v.Duration
            }
            Register-ScheduledTask -TaskName $dialTaskName -Action $action -Trigger @($tLogon, $tRepeat) `
                -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        } catch {
            $lastError = $_.Exception.Message
            Write-GuardLog -Level Warn -Message ("注册尝试失败（{0}）: {1}" -f $v.Name, ($lastError -replace "`r?`n", ' '))
            continue
        }

        # 回读校验：必须是 2 个触发器，且其中之一带重复间隔
        $verify = $null
        try { $verify = Get-ScheduledTask -TaskName $dialTaskName -ErrorAction Stop } catch { }
        $triggerCount = if ($verify) { @($verify.Triggers).Count } else { 0 }
        $hasRepetition = $false
        if ($verify) {
            foreach ($t in @($verify.Triggers)) {
                try { if ($t.Repetition -and $t.Repetition.Interval) { $hasRepetition = $true } } catch { }
            }
        }

        if ($triggerCount -ge 2 -and $hasRepetition) {
            Write-GuardLog -Level Info -Message ("计划任务已注册并校验通过: {0}（最高权限 / 登录触发 + 每 {1} 分钟自愈触发 / 免 UAC）触发器={2} 重复={3} 方式={4}" -f `
                $dialTaskName, $repeatMinutes, $triggerCount, $hasRepetition, $v.Name) -Data @{
                action = $argument; user = $user; triggers = $triggerCount; repetition = $v.Name
            }
            # 装完立刻把守护拉起来，不必等下一次触发
            try {
                Start-ScheduledTask -TaskName $dialTaskName -ErrorAction Stop
                Write-GuardLog -Level Info -Message "已立即启动守护（Start-ScheduledTask $dialTaskName）"
            } catch {
                Write-GuardLog -Level Warn -Message ("已注册，但立即启动失败（下次触发仍会启动）: " + $_.Exception.Message)
            }
            return 0
        }

        Write-GuardLog -Level Warn -Message ("注册后回读校验不通过（触发器={0} 重复={1}，方式={2}），试下一种写法" -f $triggerCount, $hasRepetition, $v.Name)
    }

    # 两种写法都不行才回退，并且**明确报警**：这种模式没有自愈
    Write-GuardLog -Level Error -Message ("两种重复触发器写法都失败（最后错误: {0}），回退到 schtasks（只有登录触发、没有自愈）" -f ($lastError -replace "`r?`n", ' '))
    $tr  = 'powershell.exe ' + $argument
    $out = & schtasks.exe /create /tn $dialTaskName /sc onlogon /rl HIGHEST /f /tr $tr 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-GuardLog -Level Warn -Message "计划任务已注册(schtasks 回退模式): $dialTaskName —— 只有登录触发，**没有**自愈触发"
        return 0
    }
    Write-GuardLog -Level Error -Message "计划任务注册失败: $out" -Data @{ exit = $LASTEXITCODE }
    return 2
}

function Uninstall-DialTask {
    try {
        $task = Get-ScheduledTask -TaskName $dialTaskName -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $dialTaskName -Confirm:$false -ErrorAction Stop
        Write-GuardLog -Level Info -Message "计划任务已移除: $dialTaskName"
        return 0
    } catch {
        $out = & schtasks.exe /delete /tn $dialTaskName /f 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-GuardLog -Level Info -Message "计划任务已移除(schtasks): $dialTaskName"
            return 0
        }
        Write-GuardLog -Level Error -Message "计划任务移除失败: $out" -Data @{ exit = $LASTEXITCODE }
        return 2
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 状态（只读）
# ─────────────────────────────────────────────────────────────────────────────

function Get-DialTaskInfo {
    <#
        读取自启计划任务的状态。
        注意：以最高权限注册的任务，非提权进程查询可能返回"拒绝访问"——
        那不是"任务不存在"，要分开表述，否则会误导排障。
    #>
    try {
        $t = Get-ScheduledTask -TaskName $dialTaskName -ErrorAction Stop
        $i = $null
        try { $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
        return [pscustomobject]@{
            Known        = $true
            Exists       = $true
            State        = [string]$t.State
            RunLevel     = [string]$t.Principal.RunLevel
            TriggerCount = @($t.Triggers).Count
            LastRun      = $(if ($i) { [string]$i.LastRunTime } else { '' })
            LastResult   = $(if ($i) { [string]$i.LastTaskResult } else { '' })
            Error        = ''
        }
    } catch {
        $denied = ($_.Exception.Message -match '拒绝|denied')
        return [pscustomobject]@{
            Known        = $true
            Exists       = $(if ($denied) { $null } else { $false })   # $null = 存在但读不到
            State        = $(if ($denied) { '（存在，但读取需要提权）' } else { '' })
            RunLevel     = ''
            TriggerCount = 0
            LastRun      = ''
            LastResult   = ''
            Error        = $_.Exception.Message
        }
    }
}

function Show-DialStatus {
    $picture = Get-DialEnvPicture
    $cred    = Get-GuardDialCredential -SecretPath $SecretPath
    $pipe    = Test-GuardPipeAvailable -ConnectTimeoutMs 1500

    Write-GuardLog -Level Info -Message '状态查询' -Data @{
        env         = $picture.Env
        signals     = ($picture.Signals -join '; ')
        'auth'      = $picture.AuthState
        network     = $picture.NetworkText
        service     = (Get-CampusServiceState -ServiceName $config['ServiceName'])
        clientGui   = (Test-CampusClientRunning -ProcessName $config['ClientProcessName'])
        pipeFree    = $pipe.Free
        pipeReason  = $pipe.Reason
        credential  = $(if ($cred.Ok) { "$($cred.Source) 账号=$($cred.User)" } else { '缺失: ' + $cred.Error })
        elevated    = (Test-GuardElevated)
        wire        = ('{0}/{1}' -f (Get-PortalWireFormat).Encoding, (Get-PortalWireFormat).Framing)
    }

    # 注意：这里一律用 Write-Host。
    # 调用处是 `exit (Show-DialStatus)`，走管道输出的内容会被当成 exit 的实参吞掉，
    # 结果就是"表格一行都不打印"——这个坑已经踩过一次。
    Write-Host '---- 天翼校园网 终端拨号守护 ----'
    Write-Host "环境判定   : $($picture.Env)  ($($picture.Reason))"
    Write-Host "网络       : $($picture.NetworkText)"
    Write-Host "认证状态   : $($picture.AuthState)"
    Write-Host "拨号服务   : $(Get-CampusServiceState -ServiceName $config['ServiceName'])"
    Write-Host "客户端 GUI : $(Test-CampusClientRunning -ProcessName $config['ClientProcessName'])"
    Write-Host "管道空闲   : $($pipe.Free)  ($($pipe.Reason))"
    Write-Host "凭据       : $(if ($cred.Ok) { "$($cred.Source) / $($cred.User)" } else { '缺失 - ' + $cred.Error })"
    Write-Host "线上格式   : $((Get-PortalWireFormat).Encoding)/$((Get-PortalWireFormat).Framing)"
    Write-Host "已提权     : $(Test-GuardElevated)"

    $task = Get-DialTaskInfo
    Write-Host "自启任务   : $dialTaskName"
    if ($task.Exists -eq $true) {
        Write-Host "  状态     : $($task.State)   运行级别: $($task.RunLevel)"
        Write-Host "  触发器   : $($task.TriggerCount) 个（应为 2：登录 + 每 30 分钟自愈）"
        Write-Host "  上次运行 : $($task.LastRun)   结果: $($task.LastResult)"
        if ($task.LastResult -and $task.LastResult -ne '0') {
            Write-Host "  ⚠ 上次结果非 0，说明上次自动运行没成功；看 $logDirectory\dialer-$(Get-Date -Format 'yyyyMMdd').log"
        }
    } elseif ($null -eq $task.Exists) {
        Write-Host '  状态     : 存在，但读取需要提权（以管理员身份跑本命令即可看到详情）'
    } else {
        Write-Host '  状态     : 未注册 —— 双击 cmd\install-dialer.cmd 安装'
    }
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# 主调度
# ─────────────────────────────────────────────────────────────────────────────

$mode = 'Once'
if ($Watch) { $mode = 'Watch' }
elseif ($Status) { $mode = 'Status' }
elseif ($Install) { $mode = 'Install' }
elseif ($Uninstall) { $mode = 'Uninstall' }

Write-GuardLog -Level Info -Message "天翼校园网终端拨号守护 v$dialerVersion (模式: $mode)" -Data @{
    repo     = $repoRoot
    config   = $ConfigPath
    secret   = $SecretPath
    user     = (Get-GuardCurrentUser)
    elevated = (Test-GuardElevated)
    dryRun   = $config['DryRun']
}

switch ($mode) {
    'Status' { exit (Show-DialStatus) }

    'Install' {
        $code = Install-DialTask
        exit $code
    }

    'Uninstall' {
        $code = Uninstall-DialTask
        exit $code
    }

    'Once' {
        $r = Invoke-DialOnce
        Write-GuardLog -Level Info -Message "单次执行完成: 环境=$($r.Env) 认证=$($r.AuthState) 拨号=$($r.Dialed) 退出码=$($r.ExitCode)"
        exit $r.ExitCode
    }

    'Watch' {
        $lock = Enter-GuardInstance -RepoRoot $repoRoot -Name 'dialer'
        # ★ Enter-GuardInstance 返回的是 FileStream（拿不到时返回 $null），不是带属性的对象。
        #   曾写成 `if (-not $lock.Acquired)`：FileStream 没有 .Acquired，表达式恒为真，
        #   于是 -Watch 每次启动都立刻判定"已有实例"并退出——守护一次都没真正跑起来。
        if ($null -eq $lock) {
            Write-GuardLog -Level Warn -Message '已有拨号守护实例在运行，本次启动退出'
            exit 0
        }
        Write-GuardLog -Level Info -Message "已获得单实例锁（$repoRoot\runtime\dialer.lock），进入监控循环"
        try {
            $iteration = 0
            while ($true) {
                $iteration++
                try {
                    $r = Invoke-DialOnce
                    $interval = if ($r.AuthState -eq 'Authenticated' -or $r.Env -eq 'HOME') {
                        [int]$config['PollIntervalIdle']
                    } else {
                        [int]$config['PollIntervalCampus']
                    }
                    if ($interval -lt 10) { $interval = 10 }
                } catch {
                    Write-GuardLog -Level Error -Message "拨号循环异常: $($_.Exception.Message)"
                    $interval = [int]$config['PollIntervalCampus']
                }
                if ($MaxIterations -gt 0 -and $iteration -ge $MaxIterations) {
                    Write-GuardLog -Level Info -Message "已达到 MaxIterations=$MaxIterations，退出循环"
                    break
                }
                Write-GuardLog -Level Debug -Message "休眠 $interval 秒后进入下一轮"
                Start-Sleep -Seconds $interval
            }
        } finally {
            Exit-GuardInstance -Lock $lock | Out-Null
        }
        exit 0
    }
}