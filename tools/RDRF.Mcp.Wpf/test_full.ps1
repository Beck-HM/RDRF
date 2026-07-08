# RDRF MCP - Full Integration Test Suite
# Tests: strategy backup (UIA), wpf_restore (IPC+UIA), wpf_info (IPC+UIA)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$mcpWpf = Join-Path $root "tools\RDRF.Mcp.Wpf"
$mcpCore = Join-Path $root "tools\RDRF.Mcp.Core"
$testOut = Join-Path $root "tests\RDRF_TestOutput"
$storageDir = "$testOut\rdrf_full_test"
$restoreDir = "$testOut\rdrf_full_restored"
New-Item -ItemType Directory -Force -Path $storageDir, $restoreDir | Out-Null
Remove-Item "$storageDir\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$restoreDir\*" -Recurse -Force -ErrorAction SilentlyContinue

# Ensure no stale processes
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$passed = 0; $failed = 0
$testResults = @()

function Assert-True {
    param($Cond, $Msg)
    if (-not $Cond) { throw $Msg }
}

function SHA256-Hash {
    param($Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

function Backup-File {
    param($FilePath, $Strategy, $Password, $StorageDir)
    $ed = $StorageDir.Replace('\', '/')
    $ef = $FilePath.Replace('\', '/')
    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += ('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_backup","arguments":{"filePath":"' + $ef + '","strategy":"' + $Strategy + '","password":"' + $Password + '","storageDir":"' + $ed + '"}}}')
    $allReqs = $reqs -join "`n"
    $resp = $allReqs | dotnet run --project $mcpWpf -c Release --no-build 2>&1
    Start-Sleep -Seconds 2

    $indexFile = $null
    $timeout = [datetime]::Now.AddSeconds(90)
    while ([datetime]::Now -lt $timeout) {
        $indexFile = Get-ChildItem "$StorageDir\*.indrdrf" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($indexFile -ne $null) { break }
        Start-Sleep -Seconds 3
    }
    Assert-True ($indexFile -ne $null) "Backup file not found after timeout"
    Write-Host ("  Backup OK: " + $indexFile.BaseName.Substring(0, 16) + "...")

    # Close app
    '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    return $indexFile
}

function Restore-File {
    param($IndexFile, $OutputPath, $Password)
    $idxPath = ($IndexFile.FullName).Replace('\', '/')
    $outPath = $OutputPath.Replace('\', '/')
    # Via Core MCP (direct, already proven)
    $reqs = @()
    $reqs += ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"' + $idxPath + '","outputPath":"' + $outPath + '","password":"' + $Password + '"}}}')
    $resp = ($reqs -join "`n") | dotnet run --project $mcpCore -c Release --no-build 2>&1
    Assert-True ($resp -match 'outputPath' -and $resp -match 'size') "Restore via Core MCP failed: $resp"
    Assert-True (Test-Path $OutputPath) "Restored file not found"
    Write-Host ("  Core Restore OK: size=" + (Get-Item $OutputPath).Length)
}

# ============================================================================
# 1. Strategy verification with UIA tab + strategy clicks (6 strategies)
# ============================================================================
Write-Host "`n========== 1. STRATEGY BACKUP (UIA clicks) ==========" -ForegroundColor Cyan

$f = "$env:TEMP\rdfr_strat_test.bin"
$rng = New-Object System.Random(42)
$bytes = New-Object byte[] (2 * 1024 * 1024)
$rng.NextBytes($bytes)
[System.IO.File]::WriteAllBytes($f, $bytes)
$expectedHash = SHA256-Hash $f

$strategies = @("FSS1", "FSS3", "FSS5", "FSS6", "FSS6.1")
# FSS6.2 has no UI card - falls back to IPC set_strategy, test separately

foreach ($s in $strategies) {
    Write-Host ("`n--- Strategy: " + $s + " ---") -ForegroundColor Yellow
    try {
        Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue
        $idx = Backup-File $f $s "v3rify!" $storageDir
        $out = "$restoreDir\$s.dat"
        Restore-File $idx $out "v3rify!"
        $h = SHA256-Hash $out
        Assert-True ($h -eq $expectedHash) "SHA256 mismatch for $s"
        Write-Host ("  [PASS] " + $s) -ForegroundColor Green
        $testResults += ("Strategy " + $s + ": PASS")
        $passed++
    } catch {
        Write-Host ("  [FAIL] " + $s + ": " + $_.Exception.Message) -ForegroundColor Red
        $testResults += ("Strategy " + $s + ": FAIL - " + $_.Exception.Message)
        $failed++
    }
}

# Test FSS6.2 with IPC fallback
Write-Host ("`n--- Strategy: FSS6.2 (IPC fallback, no UI card) ---") -ForegroundColor Yellow
try {
    Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue
    $idx = Backup-File $f "FSS6.2" "v3rify!" $storageDir
    $out = "$restoreDir\FSS6.2.dat"
    Restore-File $idx $out "v3rify!"
    $h = SHA256-Hash $out
    Assert-True ($h -eq $expectedHash) "SHA256 mismatch for FSS6.2"
    Write-Host ("  [PASS] FSS6.2") -ForegroundColor Green
    $testResults += "Strategy FSS6.2: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] FSS6.2: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Strategy FSS6.2: FAIL - $($_.Exception.Message)"
    $failed++
}
Remove-Item $f -Force

# ============================================================================
# 2. wpf_restore (UIA tab click + IPC)
# ============================================================================
Write-Host "`n========== 2. WPF RESTORE (UIA tab + IPC) ==========" -ForegroundColor Cyan

try {
    $f2 = "$env:TEMP\rdfr_restore_test.bin"
    $rng2 = New-Object System.Random(100)
    $bytes2 = New-Object byte[] (512 * 1024)
    $rng2.NextBytes($bytes2)
    [System.IO.File]::WriteAllBytes($f2, $bytes2)
    $expectedHash2 = SHA256-Hash $f2
    Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue
    $idx2 = Backup-File $f2 "FSS3" "rest0re!" $storageDir

    # Now use wpf_restore tool (UIA tab click + IPC)
    Write-Host "  Testing wpf_restore tool..." -ForegroundColor Gray
    $originalName = [System.IO.Path]::GetFileName($f2)
    $out2 = "$restoreDir\$originalName"  # restore writes original filename to output dir
    $idxPath2 = ($idx2.FullName).Replace('\', '/')
    $outPath2 = $restoreDir.Replace('\', '/')  # output dir, not full file path
    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += ('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_restore","arguments":{"indexPath":"' + $idxPath2 + '","password":"rest0re!","outputPath":"' + $outPath2 + '"}}}')
    $resp = ($reqs -join "`n") | dotnet run --project $mcpWpf -c Release --no-build 2>&1

    # Poll for restore output file
    Write-Host "  Polling for restore output..." -ForegroundColor Gray
    $restoreTimeout = [datetime]::Now.AddSeconds(60)
    while ([datetime]::Now -lt $restoreTimeout) {
        if (Test-Path $out2) { break }
        Start-Sleep -Seconds 3
    }
    if (-not (Test-Path $out2)) { throw "Restore output file not found after 60s" }

    # Close app
    '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    $h2 = SHA256-Hash $out2
    Assert-True ($h2 -eq $expectedHash2) "wpf_restore SHA256 mismatch"
    Write-Host ("  [PASS] wpf_restore - SHA256 matches") -ForegroundColor Green
    $testResults += "wpf_restore: PASS"
    $passed++
    Remove-Item $f2 -Force
} catch {
    Write-Host ("  [FAIL] wpf_restore: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "wpf_restore: FAIL - $($_.Exception.Message)"
    $failed++
    Remove-Item $f2 -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# 3. wpf_info (UIA tab click + IPC + UIA field read)
# ============================================================================
Write-Host "`n========== 3. WPF INFO (UIA tab + IPC + UIA fields) ==========" -ForegroundColor Cyan

try {
    $f3 = "$env:TEMP\rdfr_info_test.bin"
    $rng3 = New-Object System.Random(200)
    $bytes3 = New-Object byte[] (128 * 1024)
    $rng3.NextBytes($bytes3)
    [System.IO.File]::WriteAllBytes($f3, $bytes3)
    Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue
    $idx3 = Backup-File $f3 "FSS6.1" "inf0!" $storageDir

    # Now use wpf_info tool (UIA tab click + IPC set path/password + UIA field read)
    Write-Host "  Testing wpf_info tool..." -ForegroundColor Gray
    $idxPath3 = ($idx3.FullName).Replace('\', '/')
    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += ('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_info","arguments":{"indexPath":"' + $idxPath3 + '","password":"inf0!"}}}')
    $resp = ($reqs -join "`n") | dotnet run --project $mcpWpf -c Release --no-build 2>&1

    '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    Assert-True ($resp -match 'file' -and $resp -match 'size' -and $resp -match 'strategy') "wpf_info response missing fields: $resp"
    Write-Host ("  wpf_info response: $resp") -ForegroundColor DarkGray
    Write-Host ("  [PASS] wpf_info - fields read from UI") -ForegroundColor Green
    $testResults += "wpf_info: PASS"
    $passed++
    Remove-Item $f3 -Force
} catch {
    Write-Host ("  [FAIL] wpf_info: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "wpf_info: FAIL - $($_.Exception.Message)"
    $failed++
    Remove-Item $f3 -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  FULL TEST RESULTS" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Magenta
foreach ($r in $testResults) {
    if ($r -match 'FAIL') { Write-Host ("  " + $r) -ForegroundColor Red }
    else { Write-Host ("  " + $r) -ForegroundColor Green }
}
Write-Host ""
Write-Host ("  Total: $passed PASS, $failed FAIL") -ForegroundColor Yellow

# Cleanup
Remove-Item $storageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $restoreDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done" -ForegroundColor Green
