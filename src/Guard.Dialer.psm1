<#
    Guard.Dialer.psm1
    绕开 GUI、直接指挥官方后台服务（ESurfingSvr）完成校园网认证。

    ── 为什么能这么做 ──────────────────────────────────────────────────────
    真正干活的是 Windows 服务 ESurfingSvr（加密、auth.cgi、keep.cgi 心跳全在它里面），
    客户端 GUI 只是命名管道客户端。它的协议已从客户端加密的 Web UI 代码里解出
    （见 docs\protocol-findings.md）：

        管道：\\.\pipe\ESurfingClientPipe     ← 单实例，GUI 在跑时会独占
        报文：明文 XML
              <M><OpS>Portal</OpS><OpT>Portal</OpT><OpC>命令</OpC><P>参数</P></M>

        登录三步：ClientStart → CheckEnv → PortalConnect
                  PortalConnect 的 P = <user>账号</user><password>口令</password>
                  PortalDisConnect 的 P = <src>来源</src>

    口令是明文（PAP，与服务端下发的 <auth><type>cdc-http-pap</type> 一致），
    加密信封由服务端负责 —— 本模块完全不碰那层加密。

    ── 设计原则 ────────────────────────────────────────────────────────────
    * 纯逻辑（报文拼装/转义/凭据解析）与 IO（管道读写）分离，纯逻辑可离线单测；
    * 管道分帧方式尚未实测，所以做成可探测、可配置，而不是写死；
    * 绝不猜测口令：拿不到凭据就明确失败，不静默用错值去尝试登录。
#>

# ─────────────────────────────────────────────────────────────────────────────
# 协议常量（来自 view\js\dialMgr.js，已解密核对）
# ─────────────────────────────────────────────────────────────────────────────

$script:PortalPipeName = 'ESurfingClientPipe'
$script:PortalOpS      = 'Portal'
$script:PortalOpT      = 'Portal'

$script:PortalCommands = [ordered]@{
    ClientStart           = 'ClientStart'
    ClientStartComplete   = 'ClientStartComplete'
    CheckEnv              = 'CheckEnv'
    CheckEnvResp          = 'CheckEnvResp'
    GetNetInfoResp        = 'GetNetInfoResp'
    PortalConnect         = 'PortalConnect'
    PortalConnectResp     = 'PortalConnectResp'
    PortalDisConnect      = 'PortalDisConnect'
    PortalDisconnectResp  = 'PortalDisconnectResp'
    ServerStatusResp      = 'ServerStatusResp'
    NetStateMessageResp   = 'NetStateMessageResp'
    TicketResp            = 'TicketResp'
    AppErr                = 'AppErr'
    CheckWifiResp         = 'CheckWifiResp'
    SetValue              = 'SetValue'
    GetValue              = 'GetValue'
}

# 分帧方式候选：服务端到底怎么切分报文还没实测，逐个试即可确定
$script:PortalFramings = @('Raw', 'Null', 'CrLf', 'Lf')

function Get-PortalCommand {
    <#
    .SYNOPSIS  返回已解出的服务端命令名表。
    #>
    [CmdletBinding()]
    param()
    # OrderedDictionary 没有 Clone()，手工复制一份，避免调用方改到模块内部状态
    $copy = [ordered]@{}
    foreach ($key in $script:PortalCommands.Keys) { $copy[$key] = $script:PortalCommands[$key] }
    return $copy
}

function Get-PortalPipeName {
    [CmdletBinding()]
    param()
    return $script:PortalPipeName
}

function Get-PortalFramingCandidate {
    [CmdletBinding()]
    param()
    return $script:PortalFramings
}

# ─────────────────────────────────────────────────────────────────────────────
# 纯逻辑：转义与报文拼装
# ─────────────────────────────────────────────────────────────────────────────

function ConvertTo-PortalXmlText {
    <#
    .SYNOPSIS  把任意文本转成可安全放进 XML 元素正文的形式。
    .DESCRIPTION
        口令里完全可能出现 & < >（例如含 & 的强口令）。不转义会让服务端解析出的
        口令与真实口令不一致，表现为"密码错误"，极难排查。
        必须先替换 & 再替换尖括号，否则会把已生成的实体二次转义。
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    if ($null -eq $Text) { return '' }
    $t = $Text.Replace('&', '&amp;')
    $t = $t.Replace('<', '&lt;')
    $t = $t.Replace('>', '&gt;')
    return $t
}

function New-PortalPipeMessage {
    <#
    .SYNOPSIS  按客户端实测报文格式拼一条管道消息。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OpCode,
        [AllowEmptyString()][string]$Param = ''
    )

    if ([string]::IsNullOrWhiteSpace($OpCode)) { throw 'OpCode 不能为空' }
    if ($OpCode -match '[<>&]') { throw "OpCode 含非法字符: $OpCode" }
    if ($null -eq $Param) { $Param = '' }

    return ('<M><OpS>{0}</OpS><OpT>{1}</OpT><OpC>{2}</OpC><P>{3}</P></M>' -f
        $script:PortalOpS, $script:PortalOpT, $OpCode, $Param)
}

function New-PortalConnectParam {
    <#
    .SYNOPSIS  拼 PortalConnect 的参数段 <user>…</user><password>…</password>。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Password
    )

    if ([string]::IsNullOrWhiteSpace($User)) { throw '账号不能为空' }
    return ('<user>{0}</user><password>{1}</password>' -f
        (ConvertTo-PortalXmlText -Text $User), (ConvertTo-PortalXmlText -Text $Password))
}

function New-PortalDisconnectParam {
    [CmdletBinding()]
    param([string]$Source = 'guard')
    return ('<src>{0}</src>' -f (ConvertTo-PortalXmlText -Text $Source))
}

function Get-PortalFramingBytes {
    <#
    .SYNOPSIS  把报文编成管道上真正的字节。
    .DESCRIPTION
        **线上格式已实测确认为 UTF-16LE 且无分帧**（见 docs\protocol-findings.md）：
          * probe-portal-wire 试了 4 编码 × 5 分帧共 20 种组合，
            只有 UTF16LE/Raw 被服务端记录并回应（server is running, client state is 31）；
          * UTF-8、带尾零、带 CRLF/LF、4 字节长度前缀 —— 服务端全部无视。
        这条依据来自 plugin\ServerModule.dll：它的报文模板
        <M><OpS>%s</OpS>… 是**宽字符串**，整个模块的字符串表都是 UTF-16。
        所以默认 UTF16LE，不要改回 UTF-8。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('UTF16LE', 'UTF8', 'ANSI936')][string]$Encoding = 'UTF16LE',
        [ValidateSet('Raw', 'Null', 'CrLf', 'Lf')][string]$Framing = 'Raw'
    )

    $enc = switch ($Encoding) {
        'UTF8'    { [System.Text.Encoding]::UTF8 }
        'ANSI936' { [System.Text.Encoding]::GetEncoding(936) }
        default   { [System.Text.Encoding]::Unicode }   # UTF-16LE
    }
    $body = $enc.GetBytes($Message)

    # 分帧后缀按同样的编码追加（UTF-16LE 下尾零是 2 个字节）
    $suffix = switch ($Framing) {
        'Null' { $enc.GetBytes("`0") }
        'CrLf' { $enc.GetBytes("`r`n") }
        'Lf'   { $enc.GetBytes("`n") }
        default { [byte[]]@() }
    }
    if ($suffix.Count -gt 0) { return , ($body + $suffix) }
    return , $body
}

function Get-PortalWireFormat {
    <#
    .SYNOPSIS  返回实测确认的线上格式，供调用方与测试引用，避免各处硬编码。
    #>
    [CmdletBinding()]
    param()
    return [pscustomobject]@{ Encoding = 'UTF16LE'; Framing = 'Raw'; Verified = $true }
}

# ─────────────────────────────────────────────────────────────────────────────
# IO：管道
# ─────────────────────────────────────────────────────────────────────────────

function Test-GuardPipeAvailable {
    <#
    .SYNOPSIS  管道是否有空闲实例可以连（GUI 在跑时会被独占）。
    .OUTPUTS   PSCustomObject: Free / Reason
    #>
    [CmdletBinding()]
    param(
        [string]$PipeName = $script:PortalPipeName,
        [int]$ConnectTimeoutMs = 1500
    )

    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect($ConnectTimeoutMs)
        return [pscustomobject]@{ Free = $true; Reason = 'connected' }
    } catch {
        $msg = $_.Exception.Message
        $reason = if ($msg -match 'semaphore timeout|超时|timed out') { 'busy' }
                  elseif ($msg -match 'not find|cannot find|找不到|系统找不到') { 'missing' }
                  else { 'error: ' + $msg }
        return [pscustomobject]@{ Free = $false; Reason = $reason }
    } finally {
        if ($null -ne $pipe) { try { $pipe.Dispose() } catch { } }
    }
}

function Send-GuardPortalMessage {
    <#
    .SYNOPSIS  连上管道、发一条消息、尽力读回响应。
    .OUTPUTS   PSCustomObject: Ok / Sent / Framing / ResponseText / ResponseHex / Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$PipeName = $script:PortalPipeName,
        [ValidateSet('UTF16LE', 'UTF8', 'ANSI936')][string]$Encoding = 'UTF16LE',
        [ValidateSet('Raw', 'Null', 'CrLf', 'Lf')][string]$Framing = 'Raw',
        [int]$ConnectTimeoutMs = 3000,
        [int]$ReadTimeoutMs = 3000,
        [switch]$KeepOpen
    )

    $result = [pscustomobject]@{
        Ok = $false; Sent = 0; Framing = $Framing
        ResponseText = ''; ResponseHex = ''; Error = ''
    }

    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect($ConnectTimeoutMs)
    } catch {
        $result.Error = 'connect: ' + $_.Exception.Message
        if ($null -ne $pipe) { try { $pipe.Dispose() } catch { } }
        return $result
    }

    try {
        $bytes = Get-PortalFramingBytes -Message $Message -Encoding $Encoding -Framing $Framing
        $pipe.Write($bytes, 0, $bytes.Length)
        $pipe.Flush()
        $result.Sent = $bytes.Length

        $buffer   = New-Object byte[] 16384
        $deadline = (Get-Date).AddMilliseconds($ReadTimeoutMs)
        $collected = New-Object System.Collections.Generic.List[byte]
        while ((Get-Date) -lt $deadline) {
            if (-not $pipe.IsConnected) { break }
            try { $pipe.ReadTimeout = 300; $read = $pipe.Read($buffer, 0, $buffer.Length) }
            catch { continue }
            if ($read -le 0) { continue }
            for ($i = 0; $i -lt $read; $i++) { $collected.Add($buffer[$i]) }
            if (-not $KeepOpen) { break }
        }

        $result.Sent = $bytes.Length
        if ($collected.Count -gt 0) {
            $arr = $collected.ToArray()
            # 服务端的回包同样是 UTF-16LE（已实测），按同一编码解，并去掉可能的尾零
            $replyEnc = switch ($Encoding) {
                'UTF8'    { [System.Text.Encoding]::UTF8 }
                'ANSI936' { [System.Text.Encoding]::GetEncoding(936) }
                default   { [System.Text.Encoding]::Unicode }
            }
            $result.ResponseText = $replyEnc.GetString($arr).Trim([char]0)
            $result.ResponseHex  = (($arr | ForEach-Object { $_.ToString('X2') }) -join ' ')
        }
        $result.Ok = $true
    } catch {
        $result.Error = 'io: ' + $_.Exception.Message
    } finally {
        try { $pipe.Dispose() } catch { }
    }

    return $result
}

function Invoke-GuardPortalProbe {
    <#
    .SYNOPSIS  用 ClientStart 逐个试探分帧方式，找出服务端真正接受的那一种。
    .DESCRIPTION
        只发 ClientStart（只读式查询，服务端会回 ClientStartComplete/ServerStatus），
        不触发登录、不触发断开。适合作为"终端能不能指挥服务"的第一步验证。
    #>
    [CmdletBinding()]
    param(
        [string]$PipeName = $script:PortalPipeName,
        [int]$ConnectTimeoutMs = 3000,
        [int]$ReadTimeoutMs = 2500
    )

    $msg = New-PortalPipeMessage -OpCode $script:PortalCommands.ClientStart -Param ''
    $tries = @()
    # 先试实测确认的组合（UTF16LE/Raw），再退回其它编码与分帧，便于日后回归时自动发现服务端改版
    $combos = @([pscustomobject]@{ Encoding = 'UTF16LE'; Framing = 'Raw' })
    foreach ($e in @('UTF16LE', 'UTF8', 'ANSI936')) {
        foreach ($f in $script:PortalFramings) {
            if ($e -eq 'UTF16LE' -and $f -eq 'Raw') { continue }
            $combos += [pscustomobject]@{ Encoding = $e; Framing = $f }
        }
    }
    foreach ($c in $combos) {
        $r = Send-GuardPortalMessage -Message $msg -PipeName $PipeName -Encoding $c.Encoding -Framing $c.Framing `
            -ConnectTimeoutMs $ConnectTimeoutMs -ReadTimeoutMs $ReadTimeoutMs
        $tries += [pscustomobject]@{
            Encoding = $c.Encoding
            Framing  = $c.Framing
            Ok       = $r.Ok
            Sent     = $r.Sent
            GotReply = ($r.ResponseText.Length -gt 0)
            Reply    = $r.ResponseText
            Error    = $r.Error
        }
        if ($r.Ok -and $r.ResponseText.Length -gt 0) { break }
    }
    return $tries
}

# ─────────────────────────────────────────────────────────────────────────────
# 凭据
# ─────────────────────────────────────────────────────────────────────────────

function Get-GuardDialCredential {
    <#
    .SYNOPSIS  取得拨号账号口令。取不到就明确失败，绝不猜测。
    .DESCRIPTION
        支持两种来源（优先级从上到下）：
          1) secrets 文件里的 DpapiProtected 字段（Windows DPAPI，仅本机本用户可解）；
          2) secrets 文件里的明文 User / Password 字段。
        文件默认 runtime\dial.secrets.json，可通过 -SecretPath 覆盖。
        本函数不读、不碰官方客户端的加密存储。
    #>
    [CmdletBinding()]
    param([string]$SecretPath)

    $out = [pscustomobject]@{ Ok = $false; User = ''; Password = ''; Source = ''; Error = '' }

    if ([string]::IsNullOrWhiteSpace($SecretPath) -or -not (Test-Path -LiteralPath $SecretPath)) {
        $out.Error = "找不到凭据文件: $SecretPath"
        return $out
    }

    try {
        $json = Get-Content -LiteralPath $SecretPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $out.Error = '凭据文件不是合法 JSON: ' + $_.Exception.Message
        return $out
    }

    if ($json.PSObject.Properties.Name -contains 'DpapiProtected' -and $json.DpapiProtected) {
        try {
            Add-Type -AssemblyName System.Security -ErrorAction Stop
            $blob = [Convert]::FromBase64String([string]$json.DpapiProtected)
            $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $decoded = [System.Text.Encoding]::UTF8.GetString($plain)
            $obj = $decoded | ConvertFrom-Json
            $out.User = [string]$obj.User
            $out.Password = [string]$obj.Password
            $out.Source = 'dpapi'
        } catch {
            $out.Error = 'DPAPI 解密失败: ' + $_.Exception.Message
            return $out
        }
    } elseif ($json.PSObject.Properties.Name -contains 'Password' -and $json.Password) {
        $out.User = [string]$json.User
        $out.Password = [string]$json.Password
        $out.Source = 'plain'
    } else {
        $out.Error = '凭据文件里既没有 DpapiProtected 也没有 Password'
        return $out
    }

    if ([string]::IsNullOrWhiteSpace($out.User))     { $out.Error = '凭据缺少 User';     return $out }
    if ([string]::IsNullOrEmpty($out.Password))      { $out.Error = '凭据缺少 Password'; return $out }
    $out.Ok = $true
    return $out
}

function Protect-GuardDialCredential {
    <#
    .SYNOPSIS  把账号口令打包成 DPAPI 密文（仅当前用户、本机可解），可直接写进 secrets 文件。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][string]$Password
    )
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    $payload = @{ User = $User; Password = $Password } | ConvertTo-Json -Compress
    $bytes   = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $blob    = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($blob)
}

# ─────────────────────────────────────────────────────────────────────────────
# 编排
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-GuardPortalLogin {
    <#
    .SYNOPSIS  不用 GUI，直接命令后台服务完成认证。
    .DESCRIPTION
        顺序照抄客户端：ClientStart →（等 ClientStartComplete）→ CheckEnv → PortalConnect。
        每一步的原始响应都带回来，便于失败时取证。
    .OUTPUTS   PSCustomObject: Ok / Steps / Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][string]$Password,
        [string]$PipeName = $script:PortalPipeName,
        [ValidateSet('UTF16LE', 'UTF8', 'ANSI936')][string]$Encoding = 'UTF16LE',
        [ValidateSet('Raw', 'Null', 'CrLf', 'Lf')][string]$Framing = 'Raw',
        [int]$ConnectTimeoutMs = 3000,
        [int]$ReadTimeoutMs = 3000,
        [int]$StepGapMs = 800
    )

    $steps = New-Object System.Collections.Generic.List[object]
    $out = [pscustomobject]@{ Ok = $false; Steps = $steps; Error = '' }

    $cmds = $script:PortalCommands

    # ★ 关键：三步必须走**同一条连接**。
    #   实测教训（tools\Try-PortalLogin.ps1 的 two-trial 过程）：
    #     每条报文新开一条连接时，ClientStart/CheckEnv 会被处理，
    #     但单独连接上的 PortalConnect 会被服务**彻底无视**——日志里连
    #     `portal connect start` 都不会出现。改成同一条连接后立刻成功：
    #       portal connect start → account is → authUrl → record connected
    #   GUI 也是这么做的：一条长连接跑完整个会话。服务按连接维护状态机。
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect($ConnectTimeoutMs)
    } catch {
        $out.Error = '连接管道失败: ' + $_.Exception.Message.Split([char]10)[0]
        if ($null -ne $pipe) { try { $pipe.Dispose() } catch { } }
        return $out
    }

    $replyEnc = switch ($Encoding) {
        'UTF8'    { [System.Text.Encoding]::UTF8 }
        'ANSI936' { [System.Text.Encoding]::GetEncoding(936) }
        default   { [System.Text.Encoding]::Unicode }
    }

    try {
        $sequence = @(
            [pscustomobject]@{ OpCode = $cmds.ClientStart;   Param = ''; WaitMs = 900 }
            [pscustomobject]@{ OpCode = $cmds.CheckEnv;      Param = ''; WaitMs = 1500 }
            [pscustomobject]@{ OpCode = $cmds.PortalConnect; Param = (New-PortalConnectParam -User $User -Password $Password); WaitMs = $ReadTimeoutMs }
        )

        foreach ($step in $sequence) {
            $msg   = New-PortalPipeMessage -OpCode $step.OpCode -Param $step.Param
            $bytes = Get-PortalFramingBytes -Message $msg -Encoding $Encoding -Framing $Framing
            try {
                $pipe.Write($bytes, 0, $bytes.Length)
                $pipe.Flush()
            } catch {
                $steps.Add([pscustomobject]@{
                    OpCode = $step.OpCode; Message = $msg; Ok = $false
                    Sent = 0; Reply = ''; Error = $_.Exception.Message
                })
                $out.Error = $step.OpCode + ' 写入失败: ' + $_.Exception.Message.Split([char]10)[0]
                return $out
            }

            $got = New-Object System.Collections.Generic.List[byte]
            $deadline = (Get-Date).AddMilliseconds($step.WaitMs)
            while ((Get-Date) -lt $deadline) {
                if (-not $pipe.IsConnected) { break }
                try {
                    $pipe.ReadTimeout = 300
                    $buf = New-Object byte[] 32768
                    $n = $pipe.Read($buf, 0, $buf.Length)
                } catch { continue }
                if ($n -gt 0) { for ($i = 0; $i -lt $n; $i++) { $got.Add($buf[$i]) } }
            }

            $replyText = if ($got.Count -gt 0) { $replyEnc.GetString($got.ToArray()).Trim([char]0) } else { '' }
            $steps.Add([pscustomobject]@{
                OpCode = $step.OpCode; Message = $msg; Ok = $true
                Sent = $bytes.Length; Reply = $replyText; Error = ''
            })
            if ($StepGapMs -gt 0) { Start-Sleep -Milliseconds $StepGapMs }
        }
    } finally {
        try { $pipe.Dispose() } catch { }
    }

    $out.Ok = $true
    return $out
}

function Send-GuardPortalDisconnect {
    [CmdletBinding()]
    param(
        [string]$PipeName = $script:PortalPipeName,
        [ValidateSet('UTF16LE', 'UTF8', 'ANSI936')][string]$Encoding = 'UTF16LE',
        [ValidateSet('Raw', 'Null', 'CrLf', 'Lf')][string]$Framing = 'Raw',
        [string]$Source = 'guard'
    )
    $msg = New-PortalPipeMessage -OpCode $script:PortalCommands.PortalDisConnect `
        -Param (New-PortalDisconnectParam -Source $Source)
    return Send-GuardPortalMessage -Message $msg -PipeName $PipeName -Encoding $Encoding -Framing $Framing
}

Export-ModuleMember -Function @(
    'Get-PortalCommand', 'Get-PortalPipeName', 'Get-PortalFramingCandidate',
    'ConvertTo-PortalXmlText', 'New-PortalPipeMessage', 'New-PortalConnectParam',
    'New-PortalDisconnectParam', 'Get-PortalFramingBytes', 'Get-PortalWireFormat',
    'Test-GuardPipeAvailable', 'Send-GuardPortalMessage', 'Invoke-GuardPortalProbe',
    'Get-GuardDialCredential', 'Protect-GuardDialCredential',
    'Invoke-GuardPortalLogin', 'Send-GuardPortalDisconnect'
)