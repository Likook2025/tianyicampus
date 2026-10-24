<#
    Set-DialerCredential.ps1
    录入校园网账号与口令，并用 Windows DPAPI 加密保存到 <repo>\dial.secrets.json。

    为什么要这样存
    --------------
      * 后台服务要的是**明文**口令（见 docs\protocol-findings.md），所以守护必须持有它；
      * 但绝不该明文落盘：DPAPI 加密后**只有「本机 + 本 Windows 账户」能解开**，
        拷到别的机器/别的账户都无效；
      * 该文件已被 .gitignore 排除，不会误传进版本库。

    用法
    ----
      powershell -File tools\Set-DialerCredential.ps1            # 交互录入（推荐）
      powershell -File tools\Set-DialerCredential.ps1 -Show      # 只看当前存的是哪个账号
      powershell -File tools\Set-DialerCredential.ps1 -Remove    # 删除凭据

    日常入口：双击 cmd\setup-dialer-credential.cmd
#>
[CmdletBinding()]
param(
    [string]$User,
    [switch]$Show,
    [switch]$Remove,
    [string]$SecretPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SecretPath)) { $SecretPath = Join-Path $repoRoot 'dial.secrets.json' }

Import-Module (Join-Path $repoRoot 'src\Guard.Dialer.psm1') -Force -DisableNameChecking

function Write-Head { param([string]$T) Write-Host ''; Write-Host ('=== ' + $T + ' ===') -ForegroundColor Cyan }

# ── 只看 ────────────────────────────────────────────────────────────────────
if ($Show) {
    Write-Head '当前凭据'
    $c = Get-GuardDialCredential -SecretPath $SecretPath
    if ($c.Ok) {
        Write-Host ('  文件      : ' + $SecretPath)
        Write-Host ('  账号      : ' + $c.User)
        Write-Host ('  口令      : 已保存（加密，长度 ' + $c.Password.Length + '）；不回显内容')
        Write-Host ('  保护方式  : ' + $c.Source)
    } else {
        Write-Host ('  还没有凭据: ' + $c.Error) -ForegroundColor Yellow
        Write-Host '  双击 cmd\setup-dialer-credential.cmd 录入。'
    }
    exit 0
}

# ── 删除 ────────────────────────────────────────────────────────────────────
if ($Remove) {
    Write-Head '删除凭据'
    if (Test-Path -LiteralPath $SecretPath) {
        Remove-Item -LiteralPath $SecretPath -Force
        Write-Host '  已删除。守护下次运行会因为缺凭据而拒绝拨号（不会猜）。' -ForegroundColor Yellow
    } else {
        Write-Host '  本来就不存在。'
    }
    exit 0
}

# ── 录入 ────────────────────────────────────────────────────────────────────
Write-Head '录入校园网账号口令'
Write-Host '说明：口令会用 Windows DPAPI 加密保存，只有本机 + 本 Windows 账户能解开，'
Write-Host '      不会明文落盘，也不会进入版本库。'
Write-Host ''

# 账号默认值：优先用已有的，其次从官方客户端配置里猜一个
$defaultUser = ''
$existing = Get-GuardDialCredential -SecretPath $SecretPath
if ($existing.Ok) { $defaultUser = $existing.User }
else {
    $clientConfig = Join-Path $env:APPDATA 'ChinatelecomJSPortal\Config\config.xml'
    if (Test-Path -LiteralPath $clientConfig) {
        try {
            $xml = [xml](Get-Content -LiteralPath $clientConfig -Raw -Encoding UTF8)
            $defaultUser = [string]$xml.eclient_config.Account.Portal.Val
        } catch { }
    }
}

if ([string]::IsNullOrWhiteSpace($User)) {
    $prompt = '校园网账号'
    if ($defaultUser) { $prompt += "（回车沿用 $defaultUser）" }
    $answer = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $defaultUser }
    $User = $answer
}
if ([string]::IsNullOrWhiteSpace($User)) { throw '账号不能为空' }

# 口令用 SecureString 读，避免明文回显到屏幕/控制台历史
$sec = Read-Host '校园网口令（输入时不显示）' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
if ([string]::IsNullOrEmpty($plain)) { throw '口令不能为空' }

$confirm = Read-Host '再输入一次确认' -AsSecureString
$bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm)
try {
    $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
}
if ($plain -cne $plain2) { throw '两次输入不一致，未保存' }

$blob = Protect-GuardDialCredential -User $User -Password $plain
$json = [pscustomobject]@{ DpapiProtected = $blob } | ConvertTo-Json -Compress
Set-Content -LiteralPath $SecretPath -Value $json -Encoding UTF8 -NoNewline

# 立刻回读验证，避免"写进去了但解不开"
$check = Get-GuardDialCredential -SecretPath $SecretPath
Write-Host ''
if ($check.Ok -and $check.User -eq $User -and $check.Password -eq $plain) {
    Write-Host ('✅ 已保存并回读验证通过：' + $SecretPath) -ForegroundColor Green
    Write-Host ('   账号 ' + $check.User + '，口令长度 ' + $check.Password.Length + '（加密存储）')
    Write-Host ''
    Write-Host '下一步：双击 cmd\install-dialer.cmd 注册开机自启（若已安装可跳过）。'
} else {
    Write-Host ('❌ 保存后回读失败，请重试：' + $check.Error) -ForegroundColor Red
    exit 1
}
exit 0