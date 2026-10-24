<#
    Guard.Log.psm1
    日志：按天落盘 logs\guard-yyyyMMdd.log，自动清理过期文件。
#>

$script:LogLevelRank = @{ Debug = 10; Info = 20; Warn = 30; Error = 40 }
$script:LogDir       = $null
$script:MinimumLevel = 'Info'
$script:WriteConsole = $true
$script:LogPrefix    = 'guard'

function Initialize-GuardLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [int]$RetentionDays = 14,
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')][string]$Level = 'Info',
        [string]$Prefix = 'guard',
        [switch]$NoConsole
    )

    $script:LogDir       = $Directory
    $script:MinimumLevel = $Level
    $script:LogPrefix    = $Prefix
    $script:WriteConsole = -not $NoConsole

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }
    $removed = Remove-OldGuardLogs -Directory $Directory -RetentionDays $RetentionDays -Prefix $Prefix
    return $removed
}

function Get-GuardLogFilePath {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [datetime]$Date = (Get-Date),
        [string]$Prefix = 'guard'
    )
    return (Join-Path $Directory ('{0}-{1:yyyyMMdd}.log' -f $Prefix, $Date))
}

function Get-GuardLogLevel {
    return $script:MinimumLevel
}

function Write-GuardLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')][string]$Level = 'Info',
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data
    )

    if ($script:LogLevelRank[$Level] -lt $script:LogLevelRank[$script:MinimumLevel]) { return }

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line  = "$stamp [$Level] $Message"
    if ($Data) {
        foreach ($key in $Data.Keys) {
            $value = $Data[$key]
            if ($null -eq $value) { $value = '' }
            $line += " | $key=$value"
        }
    }

    if ($script:LogDir) {
        $file = Get-GuardLogFilePath -Directory $script:LogDir -Prefix $script:LogPrefix
        try {
            # 带 BOM 的 UTF-8：Windows PowerShell 5.1 的 Get-Content 才能正确识别中文
            [System.IO.File]::AppendAllText($file, $line + "`r`n", (New-Object System.Text.UTF8Encoding($true)))
        } catch { }
    }

    if ($script:WriteConsole) {
        $color = 'Gray'
        switch ($Level) {
            'Info'  { $color = 'Gray' }
            'Debug' { $color = 'DarkGray' }
            'Warn'  { $color = 'Yellow' }
            'Error' { $color = 'Red' }
        }
        Write-Host $line -ForegroundColor $color
    }
}

function Remove-OldGuardLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [int]$RetentionDays = 14,
        [string]$Prefix = 'guard',
        [datetime]$Now = (Get-Date)
    )

    $removed = @()
    if (-not (Test-Path -LiteralPath $Directory)) { return $removed }
    $cutoff = $Now.Date.AddDays(-1 * $RetentionDays)
    $files  = @(Get-ChildItem -LiteralPath $Directory -Filter "$Prefix-*.log" -File -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        if ($file.LastWriteTime -lt $cutoff) {
            try {
                Remove-Item -LiteralPath $file.FullName -Force
                $removed += $file.FullName
            } catch { }
        }
    }
    return $removed
}
