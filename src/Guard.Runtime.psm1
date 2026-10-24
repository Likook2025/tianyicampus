<#
    Guard.Runtime.psm1
    运行时基础设施：配置加载与校验、单实例锁、路径解析。
    所有对外函数都设计为可离线测试（不依赖真实网络/注册表/系统状态）。
#>

$script:GuardVersion = '1.0.0'

$script:DefaultConfig = [ordered]@{
    ClientExePath           = ''
    ClientExeName           = 'ESurfingClient.exe'
    ClientProcessName       = 'ESurfingClient'
    ServiceName             = 'ESurfingSvr'
    NeutralProbeUrl         = 'http://www.msftconnecttest.com/connecttest.txt'
    NeutralProbeExpectedContent = 'Microsoft Connect Test'
    ProbeTimeoutSec         = 5
    PortalHosts             = @('124.232.225.*', '175.12.104.*', '*.189.cn')
    ContentMarkers          = @('detect.html', 'wlanuserip', '189.cn', 'auth.cgi')
    CampusCidr              = '100.64.0.0/10'
    CampusGateway           = '100.67.192.1'
    EnablePortalDetectProbe = $false
    PortalDetectUrl         = 'http://124.232.225.17:10001/detect.html'
    PollIntervalCampus      = 20
    PollIntervalIdle        = 120
    ServiceStartSettleSec   = 8
    DialAttempts            = 3
    DialRetryGapSec         = 12
    NetworkReadyTimeoutSec  = 90
    AuthTimeout             = 300
    OnceVerifyTimeoutSec    = 60
    RestartPerHourMax       = 3
    HomeAction              = 'None'
    LaunchWindowStyle       = 'Normal'
    LogRetentionDays        = 14
    LogLevel                = 'Info'
    DryRun                  = $false
    TaskName                = 'TianyicampusGuard'
    LoginClickEnabled       = $true
    LoginClickUseUia        = $true
    LoginClickWaitSec       = 8
    LoginClickMinIntervalSec = 20
    LoginClickPerHourMax    = 8
    LoginClickRetryCount    = 2
    LoginClickVerifySec     = 18
    LoginButtonFracX        = 0.5
    LoginButtonFracY        = 0.575
    MinimizeClientAfterLogin = $true
    MinimizePortalPopup     = $true
    PortalPopupTitlePatterns = @('175.12.104.', '124.232.225.', '189.cn', '天翼校园', '校园网', 'wlanuserip')
    BrowserProcessNames     = @('msedge', 'chrome', 'firefox', 'iexplore', '360se', '360chrome', 'sogouexplorer', 'qqbrowser', '2345explorer', 'opera', 'brave', 'vivaldi')
}

$script:IntRules = [ordered]@{
    ProbeTimeoutSec        = @(1, 120)
    PollIntervalCampus     = @(5, 3600)
    PollIntervalIdle       = @(5, 3600)
    NetworkReadyTimeoutSec = @(5, 3600)
    AuthTimeout            = @(30, 86400)
    OnceVerifyTimeoutSec   = @(5, 3600)
    ServiceStartSettleSec  = @(0, 120)
    DialAttempts           = @(1, 10)
    DialRetryGapSec        = @(1, 300)
    RestartPerHourMax      = @(0, 60)
    LogRetentionDays       = @(1, 3650)
    LoginClickWaitSec      = @(0, 300)
    LoginClickMinIntervalSec = @(5, 3600)
    LoginClickPerHourMax   = @(0, 200)
    LoginClickRetryCount   = @(1, 5)
    LoginClickVerifySec    = @(3, 60)
}

$script:DoubleRules = [ordered]@{
    LoginButtonFracX = @(0.0, 1.0)
    LoginButtonFracY = @(0.0, 1.0)
}

$script:ArrayKeys  = @('PortalHosts', 'ContentMarkers')
$script:BoolKeys   = @('EnablePortalDetectProbe', 'DryRun', 'LoginClickEnabled', 'LoginClickUseUia', 'MinimizeClientAfterLogin', 'MinimizePortalPopup')
$script:EnumValues = @{
    HomeAction        = @('None', 'StopClient')
    LaunchWindowStyle = @('Normal', 'Minimized', 'Hidden')
    LogLevel          = @('Debug', 'Info', 'Warn', 'Error')
}

function Get-GuardVersion {
    return $script:GuardVersion
}

function Test-GuardElevated {
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-GuardWshEnabled {
    <#
        Windows Script Host 是否可用。安全软件可能禁用它，
        这种情况下不能依赖 .vbs 包装器（否则开机将什么都不发生）。
    #>
    foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings',
                        'HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings')) {
        try {
            $values = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            if ($null -ne $values.Enabled -and [int]$values.Enabled -eq 0) { return $false }
        } catch { }
    }
    return $true
}

function Get-GuardCurrentUser {
    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch {
        return "$env:USERDOMAIN\$env:USERNAME"
    }
}

function Get-GuardDefaultConfig {
    $copy = @{}
    foreach ($key in $script:DefaultConfig.Keys) {
        $value = $script:DefaultConfig[$key]
        if ($value -is [array]) { $copy[$key] = @($value) } else { $copy[$key] = $value }
    }
    return $copy
}

function Get-GuardConfigKeyDoc {
    $doc = @{}
    foreach ($key in $script:DefaultConfig.Keys) { $doc[$key] = $script:DefaultConfig[$key] }
    return $doc
}

function Import-GuardConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $values   = Get-GuardDefaultConfig
    $warnings = New-Object System.Collections.Generic.List[string]

    if (-not (Test-Path -LiteralPath $Path)) {
        $warnings.Add("配置文件不存在，已使用内置默认值: $Path")
        return [pscustomobject]@{ Values = $values; Warnings = $warnings; Path = $Path }
    }

    $raw = $null
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    } catch {
        $warnings.Add("读取配置文件失败，已使用内置默认值: $($_.Exception.Message)")
        return [pscustomobject]@{ Values = $values; Warnings = $warnings; Path = $Path }
    }

    $json = $null
    try {
        $json = $raw | ConvertFrom-Json
    } catch {
        $warnings.Add("配置文件不是合法 JSON，已使用内置默认值: $($_.Exception.Message)")
        return [pscustomobject]@{ Values = $values; Warnings = $warnings; Path = $Path }
    }

    foreach ($prop in $json.PSObject.Properties) {
        $key = [string]$prop.Name
        if (-not $values.ContainsKey($key)) {
            $warnings.Add("忽略未知配置项: $key")
            continue
        }
        $val = $prop.Value

        if ($script:IntRules.Contains($key)) {
            $parsed = 0
            if ([int]::TryParse([string]$val, [ref]$parsed)) {
                $range = $script:IntRules[$key]
                if ($parsed -lt $range[0] -or $parsed -gt $range[1]) {
                    $warnings.Add("配置项 $key 取值 $parsed 超出允许范围 [$($range[0]), $($range[1])]，已使用默认值 $($values[$key])")
                } else {
                    $values[$key] = $parsed
                }
            } else {
                $warnings.Add("配置项 $key 不是整数（$val），已使用默认值 $($values[$key])")
            }
            continue
        }

        if ($script:ArrayKeys -contains $key) {
            if ($val -is [string]) {
                $values[$key] = @([string]$val)
            } elseif ($val -is [System.Collections.IEnumerable]) {
                $values[$key] = @($val | ForEach-Object { [string]$_ })
            } else {
                $warnings.Add("配置项 $key 应为字符串数组，已使用默认值")
            }
            continue
        }

        if ($script:DoubleRules.Contains($key)) {
            $parsedDouble = 0.0
            if ([double]::TryParse([string]$val, [ref]$parsedDouble)) {
                $range = $script:DoubleRules[$key]
                if ($parsedDouble -lt $range[0] -or $parsedDouble -gt $range[1]) {
                    $warnings.Add("配置项 $key 取值 $parsedDouble 超出允许范围 [$($range[0]), $($range[1])]，已使用默认值 $($values[$key])")
                } else {
                    $values[$key] = $parsedDouble
                }
            } else {
                $warnings.Add("配置项 $key 不是数字（$val），已使用默认值 $($values[$key])")
            }
            continue
        }

        if ($script:BoolKeys -contains $key) {
            if ($val -is [bool]) {
                $values[$key] = [bool]$val
            } else {
                $parsedBool = $false
                if ([bool]::TryParse([string]$val, [ref]$parsedBool)) {
                    $values[$key] = $parsedBool
                } else {
                    $warnings.Add("配置项 $key 应为 true/false（$val），已使用默认值 $($values[$key])")
                }
            }
            continue
        }

        if ($script:EnumValues.ContainsKey($key)) {
            $allowed = $script:EnumValues[$key]
            $match   = @($allowed | Where-Object { $_ -eq [string]$val })
            if ($match.Count -gt 0) {
                $values[$key] = $match[0]
            } else {
                $warnings.Add("配置项 $key 取值 $val 不合法（允许: $($allowed -join ', ')），已使用默认值 $($values[$key])")
            }
            continue
        }

        $values[$key] = ([string]$val).Trim()
    }

    if ($values['CampusCidr'] -and ($values['CampusCidr'] -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$')) {
        $warnings.Add("配置项 CampusCidr 格式可疑: $($values['CampusCidr'])")
    }

    return [pscustomobject]@{ Values = $values; Warnings = $warnings; Path = $Path }
}

function Get-GuardRepoRoot {
    param([string]$ModuleRoot)
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) { $ModuleRoot = $PSScriptRoot }
    return (Split-Path -Parent $ModuleRoot)
}

function Get-GuardRuntimeDir {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)
    return (Join-Path $RepoRoot 'runtime')
}

function Get-GuardLogDir {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)
    return (Join-Path $RepoRoot 'logs')
}

function Get-GuardLockPath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$Name = 'guard'
    )
    return (Join-Path (Get-GuardRuntimeDir -RepoRoot $RepoRoot) "$Name.lock")
}

function Enter-GuardInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$Name = 'guard'
    )

    $runtimeDir = Get-GuardRuntimeDir -RepoRoot $RepoRoot
    if (-not (Test-Path -LiteralPath $runtimeDir)) {
        New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
    }
    $lockFile = Get-GuardLockPath -RepoRoot $RepoRoot -Name $Name
    try {
        $stream = New-Object System.IO.FileStream(
            $lockFile,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        return $stream
    } catch [System.IO.IOException] {
        return $null
    } catch {
        return $null
    }
}

function Exit-GuardInstance {
    param($Stream)
    if ($null -ne $Stream) {
        try { $Stream.Dispose() } catch { }
    }
}

function New-GuardLauncher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PowershellExe,
        [Parameter(Mandatory = $true)][string]$Argument,
        [string]$FileName = 'start-guard.cmd'
    )

    $launcherDirectory = Get-GuardRuntimeDir -RepoRoot $RepoRoot
    if (-not (Test-Path -LiteralPath $launcherDirectory)) {
        New-Item -ItemType Directory -Path $launcherDirectory -Force | Out-Null
    }
    $launcherPath = Join-Path $launcherDirectory $FileName
    $lines = @(
        '@echo off',
        "`"$PowershellExe`" $Argument"
    )
    Set-Content -LiteralPath $launcherPath -Value $lines -Encoding ASCII
    return $launcherPath
}
