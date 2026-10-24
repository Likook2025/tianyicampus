$ErrorActionPreference = 'Stop'

$testsDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot       = Split-Path -Parent $testsDirectory
$srcDirectory   = Join-Path $repoRoot 'src'

Import-Module (Join-Path $srcDirectory 'Guard.Runtime.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Log.psm1')     -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Env.psm1')     -Force -DisableNameChecking
Import-Module (Join-Path $srcDirectory 'Guard.Client.psm1')  -Force -DisableNameChecking

function New-TestSnapshot {
    param(
        [string]$IPv4,
        [string]$Gateway,
        [string]$Name = 'Ethernet'
    )
    $iface = [pscustomobject]@{
        Name        = $Name
        Description = 'test adapter'
        Type        = 'Ethernet'
        IPv4        = $IPv4
        Gateway     = $Gateway
        Dns         = @('222.246.129.81')
    }
    return [pscustomobject]@{
        HasGateway = -not [string]::IsNullOrWhiteSpace($Gateway)
        Primary    = $iface
        Interfaces = @($iface)
        Source     = 'test'
        Error      = $null
    }
}

function New-TestProbe {
    param(
        [bool]$Ok = $true,
        $StatusCode = 200,
        [string]$Location = '',
        [string]$Content = '',
        [string]$ErrorText = ''
    )
    return [pscustomobject]@{
        Ok         = $Ok
        StatusCode = $StatusCode
        Location   = $Location
        Content    = $Content
        Error      = $ErrorText
        Url        = 'http://test.local'
    }
}

function New-TestConfig {
    return (Get-GuardDefaultConfig)
}

Describe 'Test-IPv4InCidr' {
    It '接受 CGNAT 网段内的校园网地址' {
        Test-IPv4InCidr -IPAddress '100.68.15.135' -Cidr '100.64.0.0/10' | Should Be $true
    }
    It '拒绝 CGNAT 网段外的地址' {
        Test-IPv4InCidr -IPAddress '192.168.1.10' -Cidr '100.64.0.0/10' | Should Be $false
    }
    It '支持 /24 前缀' {
        Test-IPv4InCidr -IPAddress '192.168.1.42' -Cidr '192.168.1.0/24' | Should Be $true
        Test-IPv4InCidr -IPAddress '192.168.2.42' -Cidr '192.168.1.0/24' | Should Be $false
    }
    It '支持 /32 与 /0' {
        Test-IPv4InCidr -IPAddress '175.12.104.1' -Cidr '175.12.104.1/32' | Should Be $true
        Test-IPv4InCidr -IPAddress '175.12.104.2' -Cidr '175.12.104.1/32' | Should Be $false
        Test-IPv4InCidr -IPAddress '8.8.8.8' -Cidr '0.0.0.0/0' | Should Be $true
    }
    It '非法输入返回 false' {
        Test-IPv4InCidr -IPAddress 'not-an-ip' -Cidr '100.64.0.0/10' | Should Be $false
        Test-IPv4InCidr -IPAddress '100.68.15.135' -Cidr 'broken' | Should Be $false
        Test-IPv4InCidr -IPAddress '' -Cidr '100.64.0.0/10' | Should Be $false
    }
}

Describe 'Test-HostPattern' {
    It '精确匹配主机名与 IP' {
        Test-HostPattern -Host_ '124.232.225.17' -Pattern '124.232.225.17' | Should Be $true
        Test-HostPattern -Host_ '124.232.225.18' -Pattern '124.232.225.17' | Should Be $false
    }
    It '通配 *.189.cn 匹配子域' {
        Test-HostPattern -Host_ 'www.189.cn' -Pattern '*.189.cn' | Should Be $true
        Test-HostPattern -Host_ '189.cn' -Pattern '*.189.cn' | Should Be $false
    }
    It '裸域名同时匹配自身与子域' {
        Test-HostPattern -Host_ '189.cn' -Pattern '189.cn' | Should Be $true
        Test-HostPattern -Host_ 'a.189.cn' -Pattern '189.cn' | Should Be $true
    }
    It '前缀通配匹配整个网段' {
        Test-HostPattern -Host_ '175.12.104.3' -Pattern '175.12.104.*' | Should Be $true
        Test-HostPattern -Host_ '175.12.104.1' -Pattern '175.12.104.*' | Should Be $true
        Test-HostPattern -Host_ '175.12.105.1' -Pattern '175.12.104.*' | Should Be $false
    }
}

Describe 'Test-PortalHijack' {
    $portalHosts    = @('124.232.225.17', '175.12.104.1', '*.189.cn')
    $contentMarkers = @('detect.html', 'wlanuserip', '189.cn', 'auth.cgi')

    It '302 跳转到门户 IP 时判定为劫持' {
        $probe = New-TestProbe -StatusCode 302 -Location 'http://124.232.225.17:10001/detect.html'
        Test-PortalHijack -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $true
    }
    It '302 跳转到 *.189.cn 时判定为劫持' {
        $probe = New-TestProbe -StatusCode 302 -Location 'http://www.189.cn/'
        Test-PortalHijack -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $true
    }
    It '响应体包含门户标记时判定为劫持' {
        $probe = New-TestProbe -StatusCode 200 -Content '<meta http-equiv="refresh" content="1; url=http://www.189.cn">'
        Test-PortalHijack -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $true
    }
    It '正常 200 响应不算劫持' {
        $probe = New-TestProbe -StatusCode 200 -Content 'Microsoft Connect Test'
        Test-PortalHijack -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $false
    }
    It '204 不算劫持' {
        $probe = New-TestProbe -StatusCode 204
        Test-PortalHijack -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $false
    }
    It '探测失败不算劫持' {
        $probe = New-TestProbe -Ok $false -StatusCode $null -ErrorText 'timeout'
        Test-PortalHijack -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $false
    }
    It '空探测结果不算劫持' {
        Test-PortalHijack -ProbeResult $null -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be $false
    }
}

Describe 'Get-AuthState' {
    $portalHosts    = @('124.232.225.17', '175.12.104.1', '*.189.cn')
    $contentMarkers = @('detect.html', 'wlanuserip', '189.cn')

    It '被劫持时返回 NotAuthenticated' {
        $probe = New-TestProbe -StatusCode 302 -Location 'http://124.232.225.17:10001/detect.html'
        Get-AuthState -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be 'NotAuthenticated'
    }
    It '拿到正常响应时返回 Authenticated' {
        $probe = New-TestProbe -StatusCode 200 -Content 'Microsoft Connect Test'
        Get-AuthState -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers -ExpectedContent 'Microsoft Connect Test' | Should Be 'Authenticated'
    }
    It '探测失败时返回 Unknown' {
        $probe = New-TestProbe -Ok $false -StatusCode $null -ErrorText 'no route'
        Get-AuthState -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers | Should Be 'Unknown'
    }
    It '200 但不是目标内容（门户页且无劫持特征）不能算已认证' {
        # 2026-10-12 实测踩过的坑：BAS 返回门户页是 200 且不含劫持特征，
        # 旧逻辑把它当成 Authenticated，于是跳过了本该执行的登录点击。
        $probe = New-TestProbe -StatusCode 200 -Content '<html><title>天翼校园</title>下载Windows版本</html>'
        Get-AuthState -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers -ExpectedContent 'Microsoft Connect Test' | Should Be 'NotAuthenticated'
    }
    It '204 视为已认证' {
        $probe = New-TestProbe -StatusCode 204
        Get-AuthState -ProbeResult $probe -PortalHosts $portalHosts -ContentMarkers $contentMarkers -ExpectedContent 'Microsoft Connect Test' | Should Be 'Authenticated'
    }
    It '跳转到门户网段（175.12.104.*）判定为劫持' {
        $probe = New-TestProbe -StatusCode 302 -Location 'http://175.12.104.3:10003/?wlanuserip=100.68.15.135'
        Test-PortalHijack -ProbeResult $probe -PortalHosts @('175.12.104.*') -ContentMarkers @() | Should Be $true
        Get-AuthState -ProbeResult $probe -PortalHosts @('175.12.104.*') -ContentMarkers @() | Should Be 'NotAuthenticated'
    }
}

Describe 'Get-EnvironmentClassification' {
    $config = New-TestConfig

    It '校园网 IP + 校园网网关判定为 CAMPUS' {
        $snapshot = New-TestSnapshot -IPv4 '100.68.15.135' -Gateway '100.67.192.1'
        $probe    = New-TestProbe -StatusCode 200 -Content 'Microsoft Connect Test'
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $probe -Config $config
        $result.Env | Should Be 'CAMPUS'
        $result.Score | Should Be 4
    }
    It '仅有门户劫持也判定为 CAMPUS' {
        $snapshot = New-TestSnapshot -IPv4 '192.168.1.20' -Gateway '192.168.1.1'
        $probe    = New-TestProbe -StatusCode 302 -Location 'http://124.232.225.17:10001/detect.html'
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $probe -Config $config
        $result.Env | Should Be 'CAMPUS'
    }
    It '家用路由器私网地址判定为 HOME' {
        $snapshot = New-TestSnapshot -IPv4 '192.168.31.88' -Gateway '192.168.31.1'
        $probe    = New-TestProbe -StatusCode 200 -Content 'Microsoft Connect Test'
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $probe -Config $config
        $result.Env | Should Be 'HOME'
        $result.Score | Should Be 0
    }
    It '只有 CGNAT 地址、没有校园网网关时判定为 UNKNOWN（保守不动作）' {
        $snapshot = New-TestSnapshot -IPv4 '100.68.15.135' -Gateway '100.67.0.1'
        $probe    = New-TestProbe -StatusCode 200 -Content 'Microsoft Connect Test'
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $probe -Config $config
        $result.Env | Should Be 'UNKNOWN'
        $result.Score | Should Be 2
    }
    It '没有活动网关时判定为 UNKNOWN' {
        $snapshot = New-TestSnapshot -IPv4 '169.254.10.20' -Gateway ''
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $null -Config $config
        $result.Env | Should Be 'UNKNOWN'
        $result.Reason | Should Be '没有可用的活动网关'
    }
    It 'ForceEnv 覆盖自动判定' {
        $snapshot = New-TestSnapshot -IPv4 '192.168.31.88' -Gateway '192.168.31.1'
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $null -Config $config -ForceEnv 'campus'
        $result.Env | Should Be 'CAMPUS'
        $result.Score | Should Be 999
        $forcedHome = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $null -Config $config -ForceEnv 'home'
        $forcedHome.Env | Should Be 'HOME'
    }
    It '启用门户 detect 探针且命中时补足校园网特征' {
        $localConfig = New-TestConfig
        $localConfig['EnablePortalDetectProbe'] = $true
        $snapshot = New-TestSnapshot -IPv4 '100.68.15.135' -Gateway '100.67.0.1'
        $probe    = New-TestProbe -StatusCode 200 -Content 'Microsoft Connect Test'
        $portal   = New-TestProbe -StatusCode 200 -Content '<meta http-equiv="refresh" content="1; url=http://www.189.cn">'
        $result   = Get-EnvironmentClassification -Snapshot $snapshot -ProbeResult $probe -PortalProbeResult $portal -Config $localConfig
        $result.Env | Should Be 'CAMPUS'
    }
}

Describe 'Get-GuardPlan' {
    It '校园网 + 客户端未运行 → 需要拉起客户端' {
        $config = New-TestConfig
        $plan = Get-GuardPlan -Env 'CAMPUS' -AuthState 'NotAuthenticated' -Config $config -ClientRunning $false
        $plan.ShouldLaunchClient | Should Be $true
        $plan.ShouldStopClient | Should Be $false
    }
    It '校园网 + 客户端已运行 → 不重复拉起' {
        $config = New-TestConfig
        $plan = Get-GuardPlan -Env 'CAMPUS' -AuthState 'Authenticated' -Config $config -ClientRunning $true
        $plan.ShouldLaunchClient | Should Be $false
    }
    It '家庭网络默认不碰客户端' {
        $config = New-TestConfig
        $plan = Get-GuardPlan -Env 'HOME' -AuthState 'Authenticated' -Config $config -ClientRunning $true
        $plan.ShouldLaunchClient | Should Be $false
        $plan.ShouldStopClient | Should Be $false
    }
    It 'HomeAction=StopClient 时停止已运行的客户端' {
        $config = New-TestConfig
        $config['HomeAction'] = 'StopClient'
        $plan = Get-GuardPlan -Env 'HOME' -AuthState 'Authenticated' -Config $config -ClientRunning $true
        $plan.ShouldStopClient | Should Be $true
    }
    It 'UNKNOWN 环境保持不动' {
        $config = New-TestConfig
        $plan = Get-GuardPlan -Env 'UNKNOWN' -AuthState 'Unknown' -Config $config -ClientRunning $false
        $plan.ShouldLaunchClient | Should Be $false
        $plan.ShouldStopClient | Should Be $false
    }
}

Describe 'Import-GuardConfig' {
    It '缺少配置文件时使用内置默认值并给出告警' {
        $missing = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-missing-' + [guid]::NewGuid().ToString('N') + '.json')
        $result = Import-GuardConfig -Path $missing
        $result.Values['CampusGateway'] | Should Be '100.67.192.1'
        $result.Warnings.Count | Should Be 1
    }
    It '合并有效覆盖值' {
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-ok-' + [guid]::NewGuid().ToString('N') + '.json')
        '{"CampusGateway":"10.0.0.1","PollIntervalIdle":300,"HomeAction":"StopClient"}' | Set-Content -LiteralPath $file -Encoding UTF8
        try {
            $result = Import-GuardConfig -Path $file
            $result.Values['CampusGateway'] | Should Be '10.0.0.1'
            $result.Values['PollIntervalIdle'] | Should Be 300
            $result.Values['HomeAction'] | Should Be 'StopClient'
            $result.Warnings.Count | Should Be 0
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    It '非法取值回退默认值并给出告警' {
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-bad-' + [guid]::NewGuid().ToString('N') + '.json')
        '{"PollIntervalIdle":"abc","HomeAction":"Shutdown","LogLevel":"Loud","UnknownKey":1}' | Set-Content -LiteralPath $file -Encoding UTF8
        try {
            $result = Import-GuardConfig -Path $file
            $result.Values['PollIntervalIdle'] | Should Be 120
            $result.Values['HomeAction'] | Should Be 'None'
            $result.Values['LogLevel'] | Should Be 'Info'
            $result.Warnings.Count | Should Be 4
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    It '非法 JSON 回退默认值' {
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-json-' + [guid]::NewGuid().ToString('N') + '.json')
        '{ this is not json' | Set-Content -LiteralPath $file -Encoding UTF8
        try {
            $result = Import-GuardConfig -Path $file
            $result.Values['NeutralProbeUrl'] | Should Be 'http://www.msftconnecttest.com/connecttest.txt'
            $result.Warnings.Count | Should Be 1
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    It '字符串数组项允许写成单个字符串' {
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-array-' + [guid]::NewGuid().ToString('N') + '.json')
        '{"PortalHosts":"10.1.2.3"}' | Set-Content -LiteralPath $file -Encoding UTF8
        try {
            $result = Import-GuardConfig -Path $file
            $result.Values['PortalHosts'].Count | Should Be 1
            $result.Values['PortalHosts'][0] | Should Be '10.1.2.3'
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    It '仓库自带配置可被正确解析' {
        $shipped = Join-Path $repoRoot 'config\guard.config.json'
        $result = Import-GuardConfig -Path $shipped
        $result.Warnings.Count | Should Be 0
        $result.Values['CampusCidr'] | Should Be '100.64.0.0/10'
        $result.Values['TaskName'] | Should Be 'TianyicampusDialer'
    }
}

Describe 'Resolve-ClientExePath' {
    $checker = { param($candidate) $candidate -eq 'D:\tools\Chinatelecom_JSPortal\ESurfingClient.exe' }

    It '优先采用配置中的路径' {
        $result = Resolve-ClientExePath -ConfiguredPath 'D:\tools\Chinatelecom_JSPortal\ESurfingClient.exe' `
            -ServiceImagePath '"D:\other\ESurfingSvr.exe"' -PathChecker $checker
        $result.Path | Should Be 'D:\tools\Chinatelecom_JSPortal\ESurfingClient.exe'
        $result.Source | Should Be 'config'
    }
    It '配置路径不存在时回退到服务 ImagePath 推导' {
        $result = Resolve-ClientExePath -ConfiguredPath 'D:\nope\ESurfingClient.exe' `
            -ServiceImagePath '"D:\tools\Chinatelecom_JSPortal\ESurfingSvr.exe"' -PathChecker $checker
        $result.Path | Should Be 'D:\tools\Chinatelecom_JSPortal\ESurfingClient.exe'
        $result.Source | Should Be 'service'
        ($result.Error -like '*ClientExePath*') | Should Be $true
    }
    It '两者都不可用时返回 none 与错误说明' {
        $result = Resolve-ClientExePath -ConfiguredPath '' -ServiceImagePath '"D:\nope\ESurfingSvr.exe"' -PathChecker $checker
        $result.Path | Should Be $null
        $result.Source | Should Be 'none'
        [bool]$result.Error | Should Be $true
    }
}

Describe 'Remove-OldGuardLogs' {
    It '删除过期日志、保留新日志' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-logs-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $oldFile = Join-Path $dir 'guard-20200101.log'
            $newFile = Join-Path $dir 'guard-20990101.log'
            'old' | Set-Content -LiteralPath $oldFile -Encoding UTF8
            'new' | Set-Content -LiteralPath $newFile -Encoding UTF8
            (Get-Item -LiteralPath $oldFile).LastWriteTime = (Get-Date).AddDays(-30)
            $removed = Remove-OldGuardLogs -Directory $dir -RetentionDays 14
            $removed.Count | Should Be 1
            (Test-Path -LiteralPath $oldFile) | Should Be $false
            (Test-Path -LiteralPath $newFile) | Should Be $true
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe '单实例锁' {
    It '同一时刻只允许一个实例持有锁' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-lock-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $first = Enter-GuardInstance -RepoRoot $dir -Name 'unit-test'
            ($null -ne $first) | Should Be $true
            $second = Enter-GuardInstance -RepoRoot $dir -Name 'unit-test'
            ($null -eq $second) | Should Be $true
            Exit-GuardInstance -Stream $first
            $third = Enter-GuardInstance -RepoRoot $dir -Name 'unit-test'
            ($null -ne $third) | Should Be $true
            Exit-GuardInstance -Stream $third
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'New-GuardLauncher' {
    It '生成带 @echo off 与正确命令行的启动器' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-launcher-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $argument = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\repo\src\TianyicampusGuard.ps1" -Watch'
            $launcher = New-GuardLauncher -RepoRoot $dir -PowershellExe $exe -Argument $argument
            (Test-Path -LiteralPath $launcher) | Should Be $true
            ($launcher -like '*runtime*start-guard.cmd') | Should Be $true
            $content = @(Get-Content -LiteralPath $launcher -Encoding ASCII)
            $content[0] | Should Be '@echo off'
            ($content[1] -like "*$exe*") | Should Be $true
            ($content[1] -like '*-Watch*') | Should Be $true
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-ClientLoginState（点击安全闸门）' {
    function New-TestClientLog {
        param([string[]]$Lines)
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-clog-' + [guid]::NewGuid().ToString('N') + '.log')
        $Lines | Set-Content -LiteralPath $file -Encoding UTF8
        return $file
    }

    It '最后出现 record connected 视为已连接' {
        $file = New-TestClientLog -Lines @(
            '2026-10-12 21:48:20.1 - waiting for authentication.',
            '2026-10-12 21:48:27.815 - portal connect start',
            '2026-10-12 21:48:30.7 - record connected'
        )
        try { Get-ClientLoginState -LogFile $file | Should Be 'Connected' }
        finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    It '最后出现 waiting for authentication 视为未连接' {
        $file = New-TestClientLog -Lines @(
            '2026-10-12 22:36:20.1 - record connected',
            '2026-10-12 22:36:34.352 - waiting for authentication.',
            '2026-10-12 22:36:39.477 - waiting for authentication.'
        )
        try { Get-ClientLoginState -LogFile $file | Should Be 'Disconnected' }
        finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    It '心跳成功视为已连接' {
        $file = New-TestClientLog -Lines @(
            '2026-10-12 22:11:28.333 - record connected',
            '2026-10-12 22:16:28.858 - KeepPluseThread url is http://175.12.104.1:10001/keep.cgi, ret 1, code 0'
        )
        try { Get-ClientLoginState -LogFile $file | Should Be 'Connected' }
        finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    It '无关日志视为未知' {
        $file = New-TestClientLog -Lines @('2026-10-12 22:00:00.1 - log start')
        try { Get-ClientLoginState -LogFile $file | Should Be 'Unknown' }
        finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    It '文件不存在视为未知' {
        Get-ClientLoginState -LogFile (Join-Path ([System.IO.Path]::GetTempPath()) 'no-such-guard-log.log') | Should Be 'Unknown'
    }
    It '带 -Since 时忽略上次会话留下的旧状态' {
        $file = New-TestClientLog -Lines @(
            '2026-10-12 22:00:00.100 - record connected',
            '2026-10-12 22:00:05.100 - KeepPluseThread url is http://175.12.104.1:10001/keep.cgi, ret 1, code 0',
            '2026-10-13 08:30:05.100 - waiting for authentication.'
        )
        try {
            $since = Get-Date -Year 2026 -Month 10 -Day 13 -Hour 8 -Minute 30 -Second 0
            Get-ClientLoginState -LogFile $file -Since $since | Should Be 'Disconnected'
            Get-ClientLoginState -LogFile $file | Should Be 'Disconnected'
        } finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    It '带 -Since 时新会话的连接记录仍能识别' {
        $file = New-TestClientLog -Lines @(
            '2026-10-12 22:00:00.100 - waiting for authentication.',
            '2026-10-13 08:30:05.100 - record connected'
        )
        try {
            $since = Get-Date -Year 2026 -Month 10 -Day 13 -Hour 8 -Minute 30 -Second 0
            Get-ClientLoginState -LogFile $file -Since $since | Should Be 'Connected'
        } finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    It '-Since 为 $null 时不应抛异常（查不到客户端进程启动时间时就会这样）' {
        # 回归：-Since 曾声明为不可空的 [datetime]，调用方传 $null 会让整个守护崩在
        # "Cannot convert null to type System.DateTime"，而不是降级为 Unknown/正常判定。
        $file = New-TestClientLog -Lines @(
            '2026-10-12 22:00:00.100 - record connected'
        )
        try {
            { Get-ClientLoginState -LogFile $file -Since $null } | Should Not Throw
            Get-ClientLoginState -LogFile $file -Since $null | Should Be 'Connected'
        } finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Guard.Dialer（绕过 GUI 直接指挥后台服务）' {
    Import-Module (Join-Path $srcDirectory 'Guard.Dialer.psm1') -Force -DisableNameChecking

    It '命令表包含登录三步与断开' {
        $cmds = Get-PortalCommand
        $cmds.ClientStart      | Should Be 'ClientStart'
        $cmds.CheckEnv         | Should Be 'CheckEnv'
        $cmds.PortalConnect    | Should Be 'PortalConnect'
        $cmds.PortalDisConnect | Should Be 'PortalDisConnect'
    }

    It 'ClientStart 报文与服务端日志里实测到的一模一样' {
        New-PortalPipeMessage -OpCode 'ClientStart' -Param '' |
            Should Be '<M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>ClientStart</OpC><P></P></M>'
    }

    It '口令里的 & < > 必须转义（否则会变成说不清的"密码错误"）' {
        ConvertTo-PortalXmlText -Text 'a&b<c>d' | Should Be 'a&amp;b&lt;c&gt;d'
        # & 必须先替换，否则会把已生成的实体二次转义
        ConvertTo-PortalXmlText -Text '&amp;' | Should Be '&amp;amp;'
    }

    It 'PortalConnect 参数段格式正确' {
        New-PortalConnectParam -User '13800000000' -Password 'p&w' |
            Should Be '<user>13800000000</user><password>p&amp;w</password>'
    }

    It 'PortalDisConnect 参数段格式正确' {
        New-PortalDisconnectParam -Source 'guard' | Should Be '<src>guard</src>'
    }

    It '线上格式默认为实测确认的 UTF-16LE 裸报文' {
        # 依据：probe-portal-wire 实测 4 编码 × 5 分帧共 20 种组合，
        # 只有 UTF16LE/Raw 被服务端记录并回应；plugin\ServerModule.dll 的报文模板也是宽字符串。
        $wf = Get-PortalWireFormat
        $wf.Encoding | Should Be 'UTF16LE'
        $wf.Framing  | Should Be 'Raw'
        # '<M>' 的 UTF-16LE 字节 = 3C 00 4D 00 3E 00
        ((Get-PortalFramingBytes -Message '<M>') -join ',') | Should Be '60,0,77,0,62,0'
    }

    It '显式指定编码与分帧时的字节正确' {
        ((Get-PortalFramingBytes -Message 'X' -Encoding UTF8 -Framing 'Raw')    -join ',') | Should Be '88'
        ((Get-PortalFramingBytes -Message 'X' -Encoding UTF8 -Framing 'Null')   -join ',') | Should Be '88,0'
        ((Get-PortalFramingBytes -Message 'X' -Encoding UTF8 -Framing 'CrLf')   -join ',') | Should Be '88,13,10'
        ((Get-PortalFramingBytes -Message 'X' -Encoding UTF8 -Framing 'Lf')     -join ',') | Should Be '88,10'
        # UTF-16LE 下尾零是 2 个字节
        ((Get-PortalFramingBytes -Message 'X' -Encoding UTF16LE -Framing 'Null') -join ',') | Should Be '88,0,0,0'
    }

    It '凭据文件缺失时明确失败，绝不猜测' {
        $r = Get-GuardDialCredential -SecretPath (Join-Path ([System.IO.Path]::GetTempPath()) 'no-such-secrets.json')
        $r.Ok | Should Be $false
        [string]::IsNullOrWhiteSpace($r.Error) | Should Be $false
    }

    It '明文凭据文件能被读出' {
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-sec-' + [guid]::NewGuid().ToString('N') + '.json')
        '{"User":"13800000000","Password":"p@ss"}' | Set-Content -LiteralPath $f -Encoding UTF8
        try {
            $r = Get-GuardDialCredential -SecretPath $f
            $r.Ok       | Should Be $true
            $r.Source   | Should Be 'plain'
            $r.User     | Should Be '13800000000'
            $r.Password | Should Be 'p@ss'
        } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    It 'DPAPI 密文可以往返（口令不必明文落盘）' {
        $blob = Protect-GuardDialCredential -User '13800000000' -Password 'p@ss'
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-sec-' + [guid]::NewGuid().ToString('N') + '.json')
        (@{ DpapiProtected = $blob } | ConvertTo-Json) | Set-Content -LiteralPath $f -Encoding UTF8
        try {
            $r = Get-GuardDialCredential -SecretPath $f
            $r.Ok       | Should Be $true
            $r.Source   | Should Be 'dpapi'
            $r.Password | Should Be 'p@ss'
        } finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    It '凭据文件里既无 Password 也无 DpapiProtected 时明确失败' {
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ('guard-sec-' + [guid]::NewGuid().ToString('N') + '.json')
        '{"User":"x"}' | Set-Content -LiteralPath $f -Encoding UTF8
        try { (Get-GuardDialCredential -SecretPath $f).Ok | Should Be $false }
        finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    It '管道被 GUI 独占时能识别为 busy 而不是抛异常' {
        # 真实环境里 GUI 在跑就是这个结果；GUI 没跑则是 Free=$true。
        # 无论哪种，都不允许抛异常。
        $r = Test-GuardPipeAvailable -ConnectTimeoutMs 500
        $r.PSObject.Properties.Name -contains 'Free' | Should Be $true
        @('connected', 'busy', 'missing') -contains $r.Reason -or $r.Reason -like 'error:*' | Should Be $true
    }
}
