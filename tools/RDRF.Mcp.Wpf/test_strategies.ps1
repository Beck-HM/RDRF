# RDRF WPF MCP - Full Strategy Verification
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$testOut = Join-Path $root "tests\RDRF_TestOutput"
$mcpWpf = Join-Path $root "tools\RDRF.Mcp.Wpf"
$mcpCore = Join-Path $root "tools\RDRF.Mcp.Core"
$testFile = "$testOut\verify_10mb.dat"
$storageDir = "$testOut\verify_backups"
$restoreDir = "$testOut\verify_restored"
New-Item -ItemType Directory -Force -Path $storageDir, $restoreDir | Out-Null
Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue
Remove-Item "$restoreDir\*" -Recurse -Force -ErrorAction SilentlyContinue

function Invoke-Mcp {
    param($Project, $JsonLines)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $tmpIn = "$env:TEMP\mcp_req.txt"
    [System.IO.File]::WriteAllText($tmpIn, $JsonLines, $utf8NoBom)
    $out = cmd /c "type `"$tmpIn`" 2>&1 | dotnet run --project `"$Project`" -c Release --no-build 2>&1"
    Remove-Item $tmpIn -Force -ErrorAction SilentlyContinue
    return $out
}

$passed = 0; $failed = 0
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "=== Creating 10MB test file ===" -ForegroundColor Cyan
$rng = New-Object System.Random(42)
$bytes = New-Object byte[] (10 * 1024 * 1024)
$rng.NextBytes($bytes)
$shaFile = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
$expectedHash = [BitConverter]::ToString($shaFile).Replace("-", "").ToLower()
[System.IO.File]::WriteAllBytes($testFile, $bytes)

$strategies = @("FSS1", "FSS3", "FSS5", "FSS6", "FSS6.1", "FSS6.2")

foreach ($strategy in $strategies) {
    Write-Host ("`n===== " + $strategy + " =====") -ForegroundColor Yellow
    Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue

    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $ef = $testFile.Replace('\', '/')
    $ed = $storageDir.Replace('\', '/')
    $reqs += ('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_backup","arguments":{"filePath":"' + $ef + '","strategy":"' + $strategy + '","password":"verify123","storageDir":"' + $ed + '"}}}')
    Invoke-Mcp $mcpWpf ($reqs -join "`n") | Out-Null

    $indexFile = $null
    $timeout = [datetime]::Now.AddSeconds(60)
    while ([datetime]::Now -lt $timeout) {
        $indexFile = Get-ChildItem "$storageDir\*.indrdrf" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($indexFile -ne $null) { break }
        Start-Sleep -Seconds 3
    }
    if ($indexFile -eq $null) { Write-Host "  FAIL (no backup)"; $failed++; continue }

    Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | Out-Null
    Start-Sleep -Seconds 2

    $restorePath = "$restoreDir\$strategy.dat"
    $idxPath = ($indexFile.FullName).Replace('\', '/')
    $outPath = $restorePath.Replace('\', '/')
    $reqRestore = @()
    $reqRestore += ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"' + $idxPath + '","outputPath":"' + $outPath + '","password":"verify123"}}}')
    $restoreResp = Invoke-Mcp $mcpCore ($reqRestore -join "`n")

    if (-not ($restoreResp -match 'outputPath' -and $restoreResp -match 'size')) { Write-Host "  FAIL (restore)"; $failed++; continue }

    Start-Sleep -Seconds 2
    if (Test-Path $restorePath) {
        $restoredBytes = [System.IO.File]::ReadAllBytes($restorePath)
        $restoredHash = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($restoredBytes)).Replace("-", "").ToLower()
        if ($restoredHash -eq $expectedHash) { Write-Host "  PASS"; $passed++ }
        else { Write-Host "  FAIL (SHA256 mismatch)"; $failed++ }
    } else { Write-Host "  FAIL (file not found)"; $failed++ }
}

Write-Host ("`nRESULTS: $passed PASS, $failed FAIL") -ForegroundColor Yellow

# Cleanup
Remove-Item $testFile -Force -ErrorAction SilentlyContinue
Remove-Item $storageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $restoreDir -Recurse -Force -ErrorAction SilentlyContinue
Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' -ErrorAction SilentlyContinue | Out-Null
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
