<#
    Guard.Env.psm1
    网络环境判定：采集网卡信息、探测 HTTP 是否被校园门户劫持、给出 CAMPUS/HOME/UNKNOWN 结论。
    判定相关的函数都是纯函数（输入输出明确），便于离线单测。
#>

$script:PrivateRanges = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')

function ConvertTo-IPv4Bytes {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        $parsed = [System.Net.IPAddress]::Parse($Text.Trim())
        $bytes  = $parsed.GetAddressBytes()
        if ($bytes.Length -ne 4) { return $null }
        return $bytes
    } catch {
        return $null
    }
}

function Test-IPv4InCidr {
    [CmdletBinding()]
    param(
        [string]$IPAddress,
        [string]$Cidr
    )

    if ([string]::IsNullOrWhiteSpace($IPAddress) -or [string]::IsNullOrWhiteSpace($Cidr)) { return $false }
    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) { return $false }

    $prefixLength = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefixLength)) { return $false }
    if ($prefixLength -lt 0 -or $prefixLength -gt 32) { return $false }

    $ipBytes  = ConvertTo-IPv4Bytes -Text $IPAddress
    $netBytes = ConvertTo-IPv4Bytes -Text $parts[0]
    if ($null -eq $ipBytes -or $null -eq $netBytes) { return $false }

    $masks = @(0, 128, 192, 224, 240, 248, 252, 254, 255)
    for ($i = 0; $i -lt 4; $i++) {
        $bits = $prefixLength - ($i * 8)
        if ($bits -le 0) { break }
        if ($bits -gt 8) { $bits = 8 }
        $mask = $masks[$bits]
        if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) { return $false }
    }
    return $true
}

function Get-HostFromUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }
    $candidate = $Url.Trim()
    try {
        if ($candidate -notmatch '^[a-zA-Z][a-zA-Z0-9+.\-]*://') {
            $candidate = 'http://' + $candidate
        }
        $uri = [System.Uri]$candidate
        return $uri.Host
    } catch {
        return ''
    }
}

function Test-HostPattern {
    [CmdletBinding()]
    param(
        [string]$Host_,
        [string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Host_) -or [string]::IsNullOrWhiteSpace($Pattern)) { return $false }
    $h = $Host_.Trim().ToLowerInvariant()
    $p = $Pattern.Trim().ToLowerInvariant()

    if ($p.StartsWith('*.')) {
        $suffix = $p.Substring(1)
        return $h.EndsWith($suffix)
    }
    if ($p.EndsWith('*')) {
        # 前缀通配：'175.12.104.*' 匹配该网段/该前缀下的所有主机
        return $h.StartsWith($p.Substring(0, $p.Length - 1))
    }
    if ($h -eq $p) { return $true }
    return $h.EndsWith('.' + $p)
}

function Test-PortalHijack {
    [CmdletBinding()]
    param(
        $ProbeResult,
        [string[]]$PortalHosts = @(),
        [string[]]$ContentMarkers = @()
    )

    if ($null -eq $ProbeResult) { return $false }

    $location = [string]$ProbeResult.Location
    if (-not [string]::IsNullOrWhiteSpace($location)) {
        $hostName = Get-HostFromUrl -Url $location
        foreach ($pattern in $PortalHosts) {
            if (Test-HostPattern -Host_ $hostName -Pattern $pattern) { return $true }
        }
    }

    $content = [string]$ProbeResult.Content
    if (-not [string]::IsNullOrWhiteSpace($content)) {
        foreach ($marker in $ContentMarkers) {
            if ([string]::IsNullOrWhiteSpace($marker)) { continue }
            if ($content.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
    }

    return $false
}

function Get-ProbeSummary {
    param($ProbeResult)
    if ($null -eq $ProbeResult) { return 'not-run' }
    if ($ProbeResult.Ok) {
        $summary = "HTTP $($ProbeResult.StatusCode)"
        if (-not [string]::IsNullOrWhiteSpace([string]$ProbeResult.Location)) {
            $summary += " -> $($ProbeResult.Location)"
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$ProbeResult.Content)) {
            $summary += " len=$(([string]$ProbeResult.Content).Length)"
        }
        return $summary
    }
    return "ERR: $($ProbeResult.Error)"
}

function Invoke-NeutralProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$TimeoutSec = 5
    )

    $result = [pscustomobject]@{
        Ok         = $false
        StatusCode = $null
        Location   = $null
        Content    = ''
        Error      = $null
        Url        = $Url
    }

    $previousProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -MaximumRedirection 0 `
            -UseBasicParsing -UserAgent 'TianyicampusGuard/1.0' -ErrorAction Stop
        $result.Ok         = $true
        $result.StatusCode = [int]$response.StatusCode
        if ($response.Headers -and $response.Headers['Location']) {
            $result.Location = [string]$response.Headers['Location']
        }
        if ($response.Content) { $result.Content = [string]$response.Content }
    } catch {
        $webResponse = $null
        $webException = $_.Exception -as [System.Net.WebException]
        if ($webException) { $webResponse = $webException.Response }
        if ($null -ne $webResponse -and $webResponse -is [System.Net.HttpWebResponse]) {
            $result.Ok         = $true
            $result.StatusCode = [int]$webResponse.StatusCode
            try {
                if ($webResponse.Headers -and $webResponse.Headers['Location']) {
                    $result.Location = [string]$webResponse.Headers['Location']
                }
            } catch { }
            try {
                $stream = $webResponse.GetResponseStream()
                if ($null -ne $stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $result.Content = [string]$reader.ReadToEnd()
                    $reader.Dispose()
                }
            } catch { }
        } else {
            $result.Error = $_.Exception.Message
        }
    } finally {
        $ProgressPreference = $previousProgress
    }

    return $result
}

function Get-NetworkSnapshotFromIpconfig {
    $result = [pscustomobject]@{
        HasGateway = $false
        Primary    = $null
        Interfaces = @()
        Source     = 'ipconfig'
        Error      = 'ipconfig 回退解析'
    }
    try {
        $text = (@(ipconfig /all) -join "`n")
    } catch {
        $result.Error = "ipconfig 执行失败: $($_.Exception.Message)"
        return $result
    }

    $ipAddress = $null
    $gateway   = $null
    $dns       = @()
    foreach ($line in ($text -split "`r?`n")) {
        $ipv4 = $null
        if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})') { $ipv4 = $matches[1] }
        if ($null -eq $ipv4) { continue }
        if ($ipv4 -eq '0.0.0.0' -or $ipv4 -like '127.*' -or $ipv4 -like '169.254.*') { continue }

        if (-not $ipAddress -and $line -match 'IPv4') { $ipAddress = $ipv4; continue }
        if (-not $gateway -and ($line -match 'Gateway' -or $line -match '网关')) { $gateway = $ipv4; continue }
        if ($line -match 'DNS' -or $line -match 'DNS 服务器') { $dns += $ipv4 }
    }

    if ($ipAddress) {
        $iface = [pscustomobject]@{
            Name        = 'ipconfig'
            Description = 'ipconfig 回退解析'
            Type        = 'Unknown'
            IPv4        = $ipAddress
            Gateway     = $gateway
            Dns         = @($dns)
        }
        $result.Primary    = $iface
        $result.Interfaces = @($iface)
        $result.HasGateway = -not [string]::IsNullOrWhiteSpace($gateway)
    }
    return $result
}

function Get-NetworkSnapshot {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        HasGateway = $false
        Primary    = $null
        Interfaces = @()
        Source     = 'none'
        Error      = $null
    }

    try {
        $rankMap   = @{ 'Ethernet' = 0; 'GigabitEthernet' = 0; 'FastEthernetFx' = 0; 'FastEthernetT' = 0; 'Wireless80211' = 1 }
        $candidates = New-Object System.Collections.Generic.List[object]

        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            $typeName = $nic.NetworkInterfaceType.ToString()
            if ($typeName -eq 'Loopback' -or $typeName -eq 'Tunnel') { continue }

            $properties = $null
            try { $properties = $nic.GetIPProperties() } catch { continue }
            if ($null -eq $properties) { continue }

            $ipAddress = $null
            foreach ($unicast in $properties.UnicastAddresses) {
                if ($unicast.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $ipAddress = $unicast.Address.ToString()
                    break
                }
            }
            if (-not $ipAddress) { continue }

            $gateway = $null
            foreach ($gw in $properties.GatewayAddresses) {
                if ($gw.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $gw.Address.ToString() -ne '0.0.0.0') {
                    $gateway = $gw.Address.ToString()
                    break
                }
            }

            $dnsServers = @()
            foreach ($dnsAddress in $properties.DnsAddresses) {
                if ($dnsAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $dnsServers += $dnsAddress.ToString()
                }
            }

            $rank = 9
            if ($rankMap.ContainsKey($typeName)) { $rank = $rankMap[$typeName] }

            $candidates.Add([pscustomobject]@{
                Name        = $nic.Name
                Description = $nic.Description
                Type        = $typeName
                Rank        = $rank
                IPv4        = $ipAddress
                Gateway     = $gateway
                Dns         = @($dnsServers)
            })
        }

        $ordered = @($candidates | Sort-Object Rank, Name)
        $result.Source     = 'dotnet'
        $result.Interfaces = $ordered

        $primary = $null
        foreach ($iface in $ordered) {
            if (-not [string]::IsNullOrWhiteSpace($iface.Gateway)) { $primary = $iface; break }
        }
        if ($null -eq $primary -and $ordered.Count -gt 0) { $primary = $ordered[0] }
        $result.Primary    = $primary
        $result.HasGateway = ($null -ne $primary -and -not [string]::IsNullOrWhiteSpace($primary.Gateway))
    } catch {
        $result.Error = $_.Exception.Message
    }

    if (-not $result.HasGateway) {
        $fallback = Get-NetworkSnapshotFromIpconfig
        if ($fallback.HasGateway) {
            $fallback.Error = $result.Error
            return $fallback
        }
        if ($result.Interfaces.Count -eq 0 -and $fallback.Interfaces.Count -gt 0) {
            $fallback.Error = $result.Error
            return $fallback
        }
    }

    return $result
}

function Test-PortalDetectResponse {
    [CmdletBinding()]
    param(
        $ProbeResult,
        [string[]]$ContentMarkers = @()
    )
    if ($null -eq $ProbeResult -or -not $ProbeResult.Ok) { return $false }
    if ($ProbeResult.StatusCode -ne 200) { return $false }
    $content = [string]$ProbeResult.Content
    if ([string]::IsNullOrWhiteSpace($content)) { return $false }
    if ($content -match 'http-equiv\s*=\s*"?refresh') { return $true }
    if ($content -match 'detect\.html') { return $true }
    foreach ($marker in $ContentMarkers) {
        if (-not [string]::IsNullOrWhiteSpace($marker) -and $content.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Get-EnvironmentClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        $ProbeResult,
        $PortalProbeResult,
        [Parameter(Mandatory = $true)]$Config,
        [ValidateSet('campus', 'home', 'none')][string]$ForceEnv = 'none'
    )

    $signals = New-Object System.Collections.Generic.List[string]

    if ($ForceEnv -ne 'none') {
        $forced = $ForceEnv.ToUpperInvariant()
        return [pscustomobject]@{
            Env     = $forced
            Score   = 999
            Signals = @("force:$ForceEnv")
            Reason  = "调试参数 ForceEnv 强制判定为 $forced"
        }
    }

    if ($null -eq $Snapshot -or -not $Snapshot.HasGateway) {
        return [pscustomobject]@{
            Env     = 'UNKNOWN'
            Score   = 0
            Signals = @()
            Reason  = '没有可用的活动网关'
        }
    }

    $score       = 0
    $cgnatHit    = $false
    $gatewayHit  = $false
    $allPrivate  = $true

    foreach ($iface in @($Snapshot.Interfaces)) {
        if ($null -eq $iface) { continue }
        if (Test-IPv4InCidr -IPAddress $iface.IPv4 -Cidr $Config.CampusCidr) {
            $cgnatHit = $true
            $signals.Add("S1(IP $($iface.IPv4) 属于 $($Config.CampusCidr))")
        }
        if (-not [string]::IsNullOrWhiteSpace($iface.Gateway) -and $iface.Gateway -eq $Config.CampusGateway) {
            $gatewayHit = $true
            $signals.Add("S2(网关 $($iface.Gateway))")
        }
        $isPrivate = $false
        foreach ($range in $script:PrivateRanges) {
            if (Test-IPv4InCidr -IPAddress $iface.IPv4 -Cidr $range) { $isPrivate = $true; break }
        }
        if (-not $isPrivate) { $allPrivate = $false }
    }

    if ($cgnatHit)  { $score += 2 }
    if ($gatewayHit) { $score += 2 }

    $hijacked = Test-PortalHijack -ProbeResult $ProbeResult -PortalHosts $Config.PortalHosts -ContentMarkers $Config.ContentMarkers
    if ($hijacked) {
        $signals.Add('S3(HTTP 被校园门户劫持)')
        $score += 3
    }

    if ($Config.EnablePortalDetectProbe -and $null -ne $PortalProbeResult) {
        if (Test-PortalDetectResponse -ProbeResult $PortalProbeResult -ContentMarkers $Config.ContentMarkers) {
            $signals.Add('S4(门户 detect 页面命中)')
            $score += 3
        }
    }

    if ($hijacked -or $score -ge 4) {
        return [pscustomobject]@{
            Env     = 'CAMPUS'
            Score   = $score
            Signals = @($signals)
            Reason  = '命中校园网特征'
        }
    }

    if ($score -eq 0) {
        $reason = '未命中任何校园网特征'
        if ($allPrivate) { $reason = '普通私网地址，判定为家庭网络' }
        return [pscustomobject]@{
            Env     = 'HOME'
            Score   = $score
            Signals = @()
            Reason  = $reason
        }
    }

    return [pscustomobject]@{
        Env     = 'UNKNOWN'
        Score   = $score
        Signals = @($signals)
        Reason  = "校园网特征不完整（得分 $score），保守起见不做动作；如确认在校园网内请检查 config 中的 CampusCidr/CampusGateway"
    }
}

function Get-AuthState {
    [CmdletBinding()]
    param(
        $ProbeResult,
        [string[]]$PortalHosts = @(),
        [string[]]$ContentMarkers = @(),
        [string]$ExpectedContent = ''
    )

    if ($null -eq $ProbeResult) { return 'Unknown' }
    if (-not $ProbeResult.Ok) { return 'Unknown' }
    if (Test-PortalHijack -ProbeResult $ProbeResult -PortalHosts $PortalHosts -ContentMarkers $ContentMarkers) {
        return 'NotAuthenticated'
    }

    # 关键：不能只凭"拿到 HTTP 响应"就认定已认证。
    # 未认证时 BAS 会返回门户页面，它可能是 200 且不含任何劫持特征，
    # 那样会被误判成"已认证"，从而跳过本该执行的登录点击（2026-10-12 实测踩过）。
    if (204 -eq [int]$ProbeResult.StatusCode) { return 'Authenticated' }
    if ([string]::IsNullOrWhiteSpace($ExpectedContent)) { return 'Unknown' }
    if ($ProbeResult.Content -and ([string]$ProbeResult.Content).IndexOf($ExpectedContent, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        return 'Authenticated'
    }
    return 'NotAuthenticated'
}

function Get-GuardPlan {
    [CmdletBinding()]
    param(
        [string]$Env,
        [string]$AuthState = 'Unknown',
        [Parameter(Mandatory = $true)]$Config,
        [bool]$ClientRunning = $false
    )

    $launch = $false
    $stop   = $false
    $reason = ''

    switch ($Env) {
        'CAMPUS' {
            if ($ClientRunning) {
                $reason = '校园网环境，客户端已在运行'
            } else {
                $launch = $true
                $reason = '校园网环境且客户端未运行，需要拉起官方客户端完成拨号'
            }
        }
        'HOME' {
            if ($Config.HomeAction -eq 'StopClient' -and $ClientRunning) {
                $stop   = $true
                $reason = '家庭网络环境，按 HomeAction=StopClient 停止官方客户端'
            } else {
                $reason = '家庭网络环境，不做任何动作'
            }
        }
        default {
            $reason = '网络环境未确定，保持不动'
        }
    }

    return [pscustomobject]@{
        Env                = $Env
        AuthState          = $AuthState
        ShouldLaunchClient = $launch
        ShouldStopClient   = $stop
        Reason             = $reason
    }
}
