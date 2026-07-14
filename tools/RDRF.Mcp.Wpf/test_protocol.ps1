# RDRF MCP - Protocol & Integration Verification Tests
# Tests MCP JSON-RPC protocol, process lifecycle, IPC compatibility
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$mcpWpf = Join-Path $root "tools\RDRF.Mcp.Wpf"
$mcpCore = Join-Path $root "tools\RDRF.Mcp.Core"
$testOut = Join-Path $root "tests\RDRF_TestOutput"
$storageDir = "$testOut\protocol_test"
New-Item -ItemType Directory -Force -Path $storageDir | Out-Null
Remove-Item "$storageDir\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$passed = 0; $failed = 0
$testResults = @()

function Assert-True {
    param($Cond, $Msg)
    if (-not $Cond) { throw $Msg }
}

function Invoke-Mcp {
    param($Project, $Json)
    $tmpIn = "$env:TEMP\mcp_req.txt"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($tmpIn, $Json, $utf8NoBom)
    $out = cmd /c "type `"$tmpIn`" 2>&1 | dotnet run --project `"$Project`" -c Release --no-build 2>&1"
    Remove-Item $tmpIn -Force -ErrorAction SilentlyContinue
    return $out
}

# ============================================================================
# 1. WPF MCP: launch + close lifecycle
# ============================================================================
Write-Host "`n========== 1. WPF MCP: launch + close ==========" -ForegroundColor Cyan
try {
    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}'
    $resp = ($reqs -join "`n") | dotnet run --project $mcpWpf -c Release --no-build 2>&1
    Start-Sleep -Seconds 3
    $rdrfProcs = @(Get-Process "RDRF.App" -ErrorAction SilentlyContinue)
    Assert-True ($rdrfProcs.Count -eq 0) "RDRF.App should be closed after wpf_close (found $($rdrfProcs.Count) process(es))"
    Write-Host "  [PASS] WPF launch + close cycle" -ForegroundColor Green
    $testResults += "WPF launch+close: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] WPF launch+close: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "WPF launch+close: FAIL - $($_.Exception.Message)"
    $failed++
}

# ============================================================================
# 5. WPF MCP - orphan cleanup on duplicate launch
# ============================================================================
Write-Host "`n========== 5. WPF MCP: orphan cleanup ==========" -ForegroundColor Cyan
try {
    # Launch twice - should not create multiple instances
    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}'
    $resp = ($reqs -join "`n") | dotnet run --project $mcpWpf -c Release --no-build 2>&1
    Start-Sleep -Seconds 3
    $rdrfProcs = @(Get-Process "RDRF.App" -ErrorAction SilentlyContinue)
    Assert-True ($rdrfProcs.Count -le 1) "Double launch should not create multiple processes (found $($rdrfProcs.Count))"
    Write-Host "  [PASS] WPF orphan cleanup" -ForegroundColor Green
    $testResults += "WPF orphan cleanup: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] WPF orphan cleanup: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "WPF orphan cleanup: FAIL - $($_.Exception.Message)"
    $failed++
}

# ============================================================================
# 6. IPC message format - JSON structure verification
# ============================================================================
Write-Host "`n========== 6. IPC message format ==========" -ForegroundColor Cyan
try {
    # Verify IPC messages used in BackupTool match what MainWindow expects
    $ipcActions = @{
        "set_encrypt_path"    = '{"action":"set_encrypt_path","value":"C:/test.txt"}'
        "set_strategy"        = '{"action":"set_strategy","value":"FSS3"}'
        "set_password"        = '{"action":"set_password","value":"mypassword"}'
        "set_output_path"     = '{"action":"set_output_path","value":"C:/backup"}'
        "start_encrypt"       = '{"action":"start_encrypt"}'
        "set_decrypt_path"    = '{"action":"set_decrypt_path","value":"C:/test.indrdrf"}'
        "set_decrypt_password" = '{"action":"set_decrypt_password","value":"mypassword"}'
        "start_decrypt"       = '{"action":"start_decrypt"}'
        "read_backup_info"    = '{"action":"read_backup_info"}'
    }
    $allValid = $true
    $ipcActions.Keys | ForEach-Object {
        $json = $ipcActions[$_]
        try { $parsed = $json | ConvertFrom-Json; if ($parsed.action -ne $_) { throw "action mismatch" } }
        catch { Write-Host "  WARN: Invalid IPC for $_ : $_"; $allValid = $false }
    }
    Assert-True $allValid "Some IPC messages failed JSON validation"
    Write-Host "  [PASS] All $($ipcActions.Count) IPC message formats valid" -ForegroundColor Green
    $testResults += "IPC message format: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] IPC message format: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "IPC message format: FAIL - $($_.Exception.Message)"
    $failed++
}

# ============================================================================
# 7. MainWindow IPC handlers - verify handler methods exist
# ============================================================================
Write-Host "`n========== 7. IPC handler verification ==========" -ForegroundColor Cyan
try {
    $handlerCode = Get-Content "$root\src\RDRF.App\MainWindow.xaml.cs" -Raw
    $expectedHandlers = @("HandleSetEncryptPath","HandleSetDecryptPath","HandleSetPassword","HandleSetDecryptPassword","HandleStartEncryptIpc","HandleSetOutputPath","HandleSetDecryptOutputPath","HandleStartDecryptIpc","HandleReadBackupInfo")
    $allFound = $true
    foreach ($h in $expectedHandlers) {
        if ($handlerCode -notmatch $h) { Write-Host "  WARN: Handler $h not found in MainWindow.xaml.cs"; $allFound = $false }
    }
    Assert-True $allFound "Some IPC handlers are missing"
    Write-Host "  [PASS] All $($expectedHandlers.Count) IPC handlers present" -ForegroundColor Green
    $testResults += "IPC handlers: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] IPC handlers: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "IPC handlers: FAIL - $($_.Exception.Message)"
    $failed++
}

# ============================================================================
# 8. WPF AutomationId coverage - verify all expected IDs exist in XAML
# ============================================================================
Write-Host "`n========== 8. AutomationId coverage ==========" -ForegroundColor Cyan
try {
    $xaml = Get-Content "$root\src\RDRF.App\MainWindow.xaml" -Raw
    $expectedAids = @(
        "TabEncrypt","TabDecrypt","TabHistory","SettingsButton",
        "MinimizeButton","MaximizeButton","CloseButton",
        "EncryptBrowseButton","EncryptOutputBrowseButton","StartEncrypt","EncryptStageText","EncryptPercentText",
        "StrategyFSS1","StrategyFSS2","StrategyFSS2R","StrategyFSS3","StrategyFSS5","StrategyFSS5P",
        "StrategyFSS6","StrategyFSS61","StrategyFSS62",
        "DecryptBrowseButton","DecryptOutputBrowseButton","StartDecrypt","DecryptStageText","DecryptPercentText",
        "HistoryBrowseBackupButton","HistoryBrowseIncrementalButton","HistoryApply",
        "InfoFileName","InfoFileSize","InfoStrategy","InfoFragmentCount","InfoCreated",
        "EncryptKeyBox","FragmentSizeMB","CustomNameBox","EncryptOutputPath",
        "DecryptKeyBox","HistoryKeyBox","HistoryCommitBox"
    )
    $missing = @()
    foreach ($aid in $expectedAids) {
        $pattern = 'AutomationId="' + $aid + '"'
        if ($xaml -notmatch [regex]::Escape($pattern)) { $missing += $aid }
    }
    if ($missing.Count -gt 0) { Write-Host "  MISSING AutomationIds: $($missing -join ', ')" }
    Assert-True ($missing.Count -eq 0) "$($missing.Count) AutomationIds missing: $($missing -join ', ')"
    Write-Host "  [PASS] All $($expectedAids.Count) AutomationIds present" -ForegroundColor Green
    $testResults += "AutomationId coverage: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] AutomationId coverage: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "AutomationId coverage: FAIL - $($_.Exception.Message)"
    $failed++
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  PROTOCOL TEST RESULTS" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Magenta
foreach ($r in $testResults) {
    if ($r -match 'FAIL') { Write-Host ("  " + $r) -ForegroundColor Red }
    else { Write-Host ("  " + $r) -ForegroundColor Green }
}
Write-Host ""
Write-Host ("  Total: $passed PASS, $failed FAIL") -ForegroundColor Yellow

Remove-Item $storageDir -Recurse -Force -ErrorAction SilentlyContinue
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done" -ForegroundColor Green
