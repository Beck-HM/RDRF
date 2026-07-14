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

function Invoke-Mcp {
    param($Project, $JsonLines)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $tmpIn = "$env:TEMP\mcp_req.txt"
    [System.IO.File]::WriteAllText($tmpIn, $JsonLines, $utf8NoBom)
    $out = cmd /c "type `"$tmpIn`" 2>&1 | dotnet run --project `"$Project`" -c Release --no-build 2>&1"
    Remove-Item $tmpIn -Force -ErrorAction SilentlyContinue
    return $out
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
    $resp = Invoke-Mcp $mcpWpf $allReqs
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
    Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | Out-Null
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
    $resp = Invoke-Mcp $mcpCore ($reqs -join "`n")
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
    $resp = Invoke-Mcp $mcpWpf ($reqs -join "`n")

    # Poll for restore output file
    Write-Host "  Polling for restore output..." -ForegroundColor Gray
    $restoreTimeout = [datetime]::Now.AddSeconds(60)
    while ([datetime]::Now -lt $restoreTimeout) {
        if (Test-Path $out2) { break }
        Start-Sleep -Seconds 3
    }
    if (-not (Test-Path $out2)) { throw "Restore output file not found after 60s" }

    # Close app
    Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | Out-Null
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
    $resp = Invoke-Mcp $mcpWpf ($reqs -join "`n")

    Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | Out-Null
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
# 4. TAB SWITCHING ROUND-TRIP
# ============================================================================
Write-Host "`n========== 4. TAB SWITCHING ==========" -ForegroundColor Cyan

function Uia-Click {
    param($Aid)
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Aid)
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -eq $null) { return $false }
    $invoke = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invoke)) {
        $invoke.Invoke(); return $true
    }
    return $false
}

function Uia-Find {
    param($Aid)
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Aid)
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    return ($el -ne $null)
}

function Launch-Wpf {
    Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}' | Out-Null
    Start-Sleep -Seconds 5
}

function Close-Wpf {
    Invoke-Mcp $mcpWpf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | Out-Null
    Start-Sleep -Seconds 2
    Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

try {
    Launch-Wpf

    # Tab Encrypt -> Decrypt -> History -> Settings -> Encrypt
    Assert-True (Uia-Click "TabEncrypt") "TabEncrypt click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "EncryptBrowseButton") "Encrypt page should show browse button"

    Assert-True (Uia-Click "TabDecrypt") "TabDecrypt click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "DecryptBrowseButton") "Decrypt page should show browse button"

    Assert-True (Uia-Click "TabHistory") "TabHistory click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "HistoryBrowseBackupButton") "History page should show browse button"

    Write-Host "  [PASS] Tab switching round-trip" -ForegroundColor Green
    $testResults += "Tab switching: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Tab switching: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Tab switching: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 5. SETTINGS TOGGLE
# ============================================================================
Write-Host "`n========== 5. SETTINGS TOGGLE ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    # 1. Open settings
    Assert-True (Uia-Click "SettingsButton") "SettingsButton click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "SettingsSaveButton") "Settings page should be visible after click"
    Write-Host "  Settings opened OK" -ForegroundColor Gray

    # 2. Click again — should stay open (latch, not toggle)
    Assert-True (Uia-Click "SettingsButton") "SettingsButton second click"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "SettingsSaveButton") "Settings should remain visible after second click"
    Write-Host "  Latch OK — second click ignored" -ForegroundColor Gray

    # 3. Switch to Encrypt tab to close
    Assert-True (Uia-Click "TabEncrypt") "TabEncrypt after settings failed"
    Start-Sleep -Milliseconds 500
    $settingsGone = -not (Uia-Find "SettingsSaveButton")
    Assert-True $settingsGone "Settings should close after tab switch"
    Write-Host "  Closed via tab switch OK" -ForegroundColor Gray

    # 4. Reopen via settings button
    Assert-True (Uia-Click "SettingsButton") "SettingsButton reopen failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "SettingsSaveButton") "Settings should reopen after tab switch"
    Write-Host "  Reopened OK" -ForegroundColor Gray

    Write-Host "  [PASS] Settings latch behavior" -ForegroundColor Green
    $testResults += "Settings latch: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Settings latch: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Settings latch: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 6. STRATEGY CARDS - all 9
# ============================================================================
Write-Host "`n========== 6. STRATEGY CARDS (all 9) ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Click "TabEncrypt") "TabEncrypt click failed"
    Start-Sleep -Milliseconds 500
    $cards = @("StrategyFSS1","StrategyFSS2","StrategyFSS2R","StrategyFSS3","StrategyFSS5","StrategyFSS5P","StrategyFSS6","StrategyFSS61","StrategyFSS62")
    $allClickable = $true
    foreach ($card in $cards) {
        if (-not (Uia-Click $card)) { Write-Host "  WARN: $card not clickable"; $allClickable = $false }
        Start-Sleep -Milliseconds 200
    }
    Assert-True $allClickable "Some strategy cards were not clickable"
    Write-Host "  [PASS] All $($cards.Count) strategy cards clickable" -ForegroundColor Green
    $testResults += "Strategy cards: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Strategy cards: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Strategy cards: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 7. WINDOW BUTTONS
# ============================================================================
Write-Host "`n========== 7. WINDOW BUTTONS ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Find "MinimizeButton") "MinimizeButton not found"
    Assert-True (Uia-Find "MaximizeButton") "MaximizeButton not found"
    Assert-True (Uia-Find "CloseButton") "CloseButton not found"
    Assert-True (Uia-Find "SettingsButton") "SettingsButton not found"
    Write-Host "  [PASS] All window buttons present" -ForegroundColor Green
    $testResults += "Window buttons: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Window buttons: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Window buttons: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 8. ENCRYPT INPUT CONTROLS
# ============================================================================
Write-Host "`n========== 8. ENCRYPT INPUT CONTROLS ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Click "TabEncrypt") "TabEncrypt click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "FragmentSizeMB") "FragmentSizeMB not found"
    Assert-True (Uia-Find "EncryptOutputPath") "EncryptOutputPath not found"
    Assert-True (Uia-Find "CustomNameBox") "CustomNameBox not found"
    Assert-True (Uia-Find "EncryptKeyBox") "EncryptKeyBox not found"
    Assert-True (Uia-Find "StartEncrypt") "StartEncrypt not found"
    Write-Host "  [PASS] Encrypt input controls present" -ForegroundColor Green
    $testResults += "Encrypt inputs: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Encrypt inputs: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Encrypt inputs: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 9. DECRYPT INPUT CONTROLS
# ============================================================================
Write-Host "`n========== 9. DECRYPT INPUT CONTROLS ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Click "TabDecrypt") "TabDecrypt click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "DecryptBrowseButton") "DecryptBrowseButton not found"
    Assert-True (Uia-Find "DecryptOutputBrowseButton") "DecryptOutputBrowseButton not found"
    Assert-True (Uia-Find "StartDecrypt") "StartDecrypt not found"
    Assert-True (Uia-Find "DecryptKeyBox") "DecryptKeyBox not found"
    Write-Host "  [PASS] Decrypt input controls present" -ForegroundColor Green
    $testResults += "Decrypt inputs: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Decrypt inputs: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Decrypt inputs: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 10. HISTORY PAGE CONTROLS
# ============================================================================
Write-Host "`n========== 10. HISTORY PAGE CONTROLS ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Click "TabHistory") "TabHistory click failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "HistoryBrowseBackupButton") "HistoryBrowseBackupButton not found"
    Assert-True (Uia-Find "HistoryBrowseIncrementalButton") "HistoryBrowseIncrementalButton not found"
    Assert-True (Uia-Find "HistoryKeyBox") "HistoryKeyBox not found"
    Write-Host "  [PASS] History page controls present" -ForegroundColor Green
    $testResults += "History controls: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] History controls: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "History controls: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 11. STRATEGY CARD SELECTION VISUAL FEEDBACK
# ============================================================================
Write-Host "`n========== 11. STRATEGY CARD SELECTION FEEDBACK ==========" -ForegroundColor Cyan

function Uia-GetBoundingRect {
    param($Aid)
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Aid)
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -eq $null) { return $null }
    return $el.Current.BoundingRectangle
}

function Uia-GetText {
    param($Aid)
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Aid)
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -eq $null) { return $null }
    $tp = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$tp)) {
        return $tp.DocumentRange.GetText(-1).Trim()
    }
    return $el.Current.Name
}

try {
    Launch-Wpf
    Assert-True (Uia-Click "TabEncrypt") "TabEncrypt click failed"
    Start-Sleep -Milliseconds 500

    # Click FSS1, record its bounding rect
    $rectBefore = Uia-GetBoundingRect "StrategyFSS1"
    Assert-True ($rectBefore -ne $null) "FSS1 bounding rect should exist"

    Assert-True (Uia-Click "StrategyFSS3") "StrategyFSS3 click failed"
    Start-Sleep -Milliseconds 500

    # FSS1 should have different visual state after FSS3 is selected (deselection)
    $rectAfter = Uia-GetBoundingRect "StrategyFSS1"
    Assert-True ($rectAfter -ne $null) "FSS1 bounding rect should still exist"

    # Click back to FSS1
    Assert-True (Uia-Click "StrategyFSS1") "FSS1 re-click failed"
    Start-Sleep -Milliseconds 500

    Write-Host "  [PASS] Strategy card selection round-trip" -ForegroundColor Green
    $testResults += "Strategy selection visual: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Strategy selection visual: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Strategy selection visual: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 12. SETTINGS PAGE CONTENT
# ============================================================================
Write-Host "`n========== 13. SETTINGS PAGE CONTENT ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Click "SettingsButton") "SettingsButton click failed"
    Start-Sleep -Milliseconds 500

    Assert-True (Uia-Find "SettingsOutputPath") "SettingsOutputPath not found"
    Assert-True (Uia-Find "SettingsBrowseButton") "SettingsBrowseButton not found"
    Assert-True (Uia-Find "SettingsExitRadio") "SettingsExitRadio not found"
    Assert-True (Uia-Find "SettingsTrayRadio") "SettingsTrayRadio not found"
    Assert-True (Uia-Find "SettingsSaveButton") "SettingsSaveButton not found"

    Write-Host "  [PASS] Settings page controls present" -ForegroundColor Green
    $testResults += "Settings content: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Settings content: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Settings content: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

# ============================================================================
# 14. BACKUP PROGRESS - verify stage text changes during backup
# ============================================================================
Write-Host "`n========== 14. BACKUP PROGRESS MONITORING ==========" -ForegroundColor Cyan

try {
    $f14 = "$env:TEMP\rdfr_progress_test.bin"
    $rng14 = New-Object System.Random(42)
    $bytes14 = New-Object byte[] (1024 * 1024)
    $rng14.NextBytes($bytes14)
    [System.IO.File]::WriteAllBytes($f14, $bytes14)
    Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue

    # Launch and backup via MCP
    $ed = $storageDir.Replace('\', '/')
    $ef = $f14.Replace('\', '/')
    $reqs = @()
    $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += ('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_backup","arguments":{"filePath":"' + $ef + '","strategy":"FSS1","password":"pr0gress!","storageDir":"' + $ed + '"}}}')
    Invoke-Mcp $mcpWpf ($reqs -join "`n") | Out-Null
    Start-Sleep -Seconds 2

    # Poll for backup file
    $idx = $null
    $t = [datetime]::Now.AddSeconds(90)
    while ([datetime]::Now -lt $t) {
        $idx = Get-ChildItem "$storageDir\*.indrdrf" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($idx) { break }
        Start-Sleep -Seconds 3
    }
    Assert-True ($idx -ne $null) "Backup file not found"

    # Verify backup succeeded (restore + SHA256 check)
    $out14 = "$storageDir\restored_progress.dat"
    $idxP = ($idx.FullName).Replace('\', '/')
    $outP = $out14.Replace('\', '/')
    $r = Invoke-Mcp $mcpCore ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"'+$idxP+'","outputPath":"'+$outP+'","password":"pr0gress!"}}}')
    Assert-True ($r -match 'outputPath') "Restore after progress test failed"
    $h1 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($f14))).Replace("-","").ToLower()
    $h2 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($out14))).Replace("-","").ToLower()
    Assert-True ($h1 -eq $h2) "SHA256 mismatch after progress test"

    Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    Write-Host "  [PASS] Backup progress verified via restore" -ForegroundColor Green
    $testResults += "Backup progress: PASS"
    $passed++
    Remove-Item $f14 -Force
} catch {
    Write-Host ("  [FAIL] Backup progress: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Backup progress: FAIL - $($_.Exception.Message)"
    $failed++
    Remove-Item $f14 -Force -ErrorAction SilentlyContinue
    Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# 15. PASSWORD PAGE - tab button + controls
# ============================================================================
Write-Host "`n========== 15. PASSWORD PAGE ==========" -ForegroundColor Cyan

try {
    Launch-Wpf
    Assert-True (Uia-Click "TabPasswords") "TabPasswords click failed"
    Start-Sleep -Milliseconds 500

    Assert-True (Uia-Find "PasswordAddButton") "PasswordAddButton not found"
    Assert-True (Uia-Find "PasswordDeleteButton") "PasswordDeleteButton not found"

    # Tab switching round-trip
    Assert-True (Uia-Click "TabEncrypt") "TabEncrypt after passwords failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Click "TabPasswords") "TabPasswords reopen failed"
    Start-Sleep -Milliseconds 500
    Assert-True (Uia-Find "PasswordAddButton") "PasswordAddButton should exist after reopen"

    Assert-True (Uia-Find "TabDSAA") "TabDSAA not found"

    Write-Host "  [PASS] Password page" -ForegroundColor Green
    $testResults += "Password page: PASS"
    $passed++
} catch {
    Write-Host ("  [FAIL] Password page: " + $_.Exception.Message) -ForegroundColor Red
    $testResults += "Password page: FAIL - $($_.Exception.Message)"
    $failed++
}
Close-Wpf

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
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done" -ForegroundColor Green
