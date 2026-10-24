<#
    Guard.Client.psm1
    官方天翼客户端的定位与进程控制；服务只做观测，不主动管理。

    编码说明：本文件必须带 UTF-8 BOM。PowerShell 5.1 对无 BOM 的 .ps1/.psm1
    按 ANSI(GBK) 解码，中文字节会被误解码，且行尾悬挂的双字节首字节会吃掉换行、
    把下一行并入注释，导致大括号失配、模块加载失败。仓库内其它脚本都带 BOM，
    本文件历史上漏了，已补上。
#>

function Get-ServiceImagePath {
    [CmdletBinding()]
    param([string]$ServiceName = 'ESurfingSvr')

    try {
        $key = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction Stop
        return [string]$key.ImagePath
    } catch {
        return $null
    }
}

function Resolve-ClientExePath {
    [CmdletBinding()]
    param(
        [string]$ConfiguredPath = '',
        [string]$ServiceImagePath,
        [string]$ExeName = 'ESurfingClient.exe',
        [scriptblock]$PathChecker
    )

    if (-not $PathChecker) {
        $PathChecker = { param($candidate) Test-Path -LiteralPath $candidate -PathType Leaf }
    }

    $errorText = $null

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        if (& $PathChecker $ConfiguredPath) {
            return [pscustomobject]@{ Path = $ConfiguredPath; Source = 'config'; Error = $null }
        }
        $errorText = "配置中的 ClientExePath 不存在: $ConfiguredPath"
    }

    if (-not [string]::IsNullOrWhiteSpace($ServiceImagePath)) {
        $clean = $ServiceImagePath.Trim().Trim('"')
        $directory = $null
        try { $directory = Split-Path -Parent $clean } catch { $directory = $null }
        if (-not [string]::IsNullOrWhiteSpace($directory)) {
            $candidate = Join-Path $directory $ExeName
            if (& $PathChecker $candidate) {
                return [pscustomobject]@{ Path = $candidate; Source = 'service'; Error = $errorText }
            }
            if (-not $errorText) { $errorText = "服务 $clean 目录下未找到 $ExeName" }
        }
    }

    if (-not $errorText) { $errorText = '既未配置 ClientExePath，也无法从拨号服务推导客户端路径' }
    return [pscustomobject]@{ Path = $null; Source = 'none'; Error = $errorText }
}

function Get-CampusClientProcess {
    [CmdletBinding()]
    param([string]$ProcessName = 'ESurfingClient')
    return @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Test-CampusClientRunning {
    [CmdletBinding()]
    param([string]$ProcessName = 'ESurfingClient')
    return ((Get-CampusClientProcess -ProcessName $ProcessName).Count -gt 0)
}

function Start-CampusClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [ValidateSet('Normal', 'Minimized', 'Hidden')][string]$WindowStyle = 'Minimized'
    )

    $workingDirectory = Split-Path -Parent $ExePath
    $process = Start-Process -FilePath $ExePath -WorkingDirectory $workingDirectory `
        -WindowStyle $WindowStyle -PassThru
    return $process
}

function Stop-CampusClient {
    [CmdletBinding()]
    param(
        [string]$ProcessName = 'ESurfingClient',
        [int]$GraceSeconds = 5
    )

    $processes = Get-CampusClientProcess -ProcessName $ProcessName
    if ($processes.Count -eq 0) { return $false }

    foreach ($process in $processes) {
        try {
            if ($process.MainWindowHandle -ne 0) { $process.CloseMainWindow() | Out-Null }
        } catch { }
    }

    $deadline = (Get-Date).AddSeconds($GraceSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-CampusClientProcess -ProcessName $ProcessName).Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }

    foreach ($process in (Get-CampusClientProcess -ProcessName $ProcessName)) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop } catch { }
    }
    return $true
}

function Get-CampusServiceState {
    [CmdletBinding()]
    param([string]$ServiceName = 'ESurfingSvr')

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return $service.Status.ToString()
    } catch {
        return 'NotFound'
    }
}

function Get-ClientLogFile {
    <#
        取客户端自己写的当天的服务日志（*_svrinfo.log）。用于判断客户端是否已认证，
        与网络探测相互独立，因此不会因为网络上不了而误判。
    #>
    [CmdletBinding()]
    param([string]$ClientExePath)

    if ([string]::IsNullOrWhiteSpace($ClientExePath)) { return $null }
    $directory = Join-Path (Split-Path -Parent $ClientExePath) 'log'
    if (-not (Test-Path -LiteralPath $directory)) { return $null }
    $file = Get-ChildItem -LiteralPath $directory -Filter '*svrinfo.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($file) { return $file.FullName }
    return $null
}

function Get-ClientLoginState {
    <#
        从客户端日志尾部推断登录状态：
          Connected    —— 出现过 record connected 或 keep.cgi 心跳成功
          Disconnected —— 出现过 record not connect / waiting for authentication / 断开
          Unknown      —— 读不到日志或没有相关行
        以"最后出现的标志"为准。

        注意 -Since 必须保持可空类型：调用方在"查不到客户端进程启动时间"时会传 $null，
        若声明成 [datetime] 会抛参数转换异常，把整个守护拖垮（见 tests 回归用例）。
        另外本文件历史上缺少 UTF-8 BOM，PowerShell 5.1 会按 ANSI 解码，
        所以参数块内不要写非 ASCII 注释（写在这里是安全的）。
    #>
    [CmdletBinding()]
    param(
        [string]$LogFile,
        [int]$TailLines = 500,
        [Nullable[datetime]]$Since
    )

    if ([string]::IsNullOrWhiteSpace($LogFile) -or -not (Test-Path -LiteralPath $LogFile)) { return 'Unknown' }
    try {
        $lines = @(Get-Content -LiteralPath $LogFile -Encoding UTF8 -Tail $TailLines -ErrorAction Stop)
    } catch {
        return 'Unknown'
    }

    $state = 'Unknown'
    foreach ($line in $lines) {
        # 需要时按时间过滤，避免把上一次会话留下的旧状态当成现在
        if ($Since) {
            $when = $null
            if ($line -match '^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2})\.(\d{1,3})') {
                try {
                    $when = Get-Date -Year ([int]$matches[1]) -Month ([int]$matches[2]) -Day ([int]$matches[3]) `
                        -Hour ([int]$matches[4]) -Minute ([int]$matches[5]) -Second ([int]$matches[6]) -Millisecond ([int]$matches[7])
                } catch { $when = $null }
            }
            if ($when -and $when -lt $Since) { continue }
        }
        if ($line -match 'record connected' -or $line -match 'KeepPluseThread .*ret 1, code 0') {
            $state = 'Connected'
        } elseif ($line -match 'record not connect' -or $line -match 'waiting for authentication' -or
                  $line -match 'client disconnect' -or $line -match 'Disconnect For') {
            $state = 'Disconnected'
        }
    }
    return $state
}
