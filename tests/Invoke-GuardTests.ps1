<#
    运行 Pester 单测并打印可读结果。
    用法: powershell -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-GuardTests.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$testsDirectory = $PSScriptRoot

Import-Module Pester -Force
$result = Invoke-Pester -Path $testsDirectory -PassThru

Write-Host ''
Write-Host ('总计 {0} 项：通过 {1}，失败 {2}，跳过 {3}' -f $result.TotalCount, $result.PassedCount, $result.FailedCount, $result.SkippedCount) `
    -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })

foreach ($test in $result.TestResult) {
    if (-not $test.Passed) {
        $message = ($test.FailureMessage -replace "`r?`n", ' ')
        Write-Host ("失败: {0} / {1}`n      {2}" -f $test.Describe, $test.Name, $message) -ForegroundColor Red
    }
}

if ($result.FailedCount -gt 0) { exit 1 }
exit 0
