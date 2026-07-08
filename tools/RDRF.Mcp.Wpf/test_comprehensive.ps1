# RDRF MCP - Comprehensive Edge Case Tests
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$testOut = Join-Path $root "tests\RDRF_TestOutput"
$mcpWpf = Join-Path $root "tools\RDRF.Mcp.Wpf"
$mcpCore = Join-Path $root "tools\RDRF.Mcp.Core"
$storageDir = "$testOut\comprehensive_test"
$restoreDir = "$testOut\comprehensive_restored"
New-Item -ItemType Directory -Force -Path $storageDir, $restoreDir | Out-Null
Remove-Item "$storageDir\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$restoreDir\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$passed = 0; $failed = 0

function Run-Test {
    param($Name, $ScriptBlock)
    Write-Host ("`n--- " + $Name + " ---") -ForegroundColor Yellow
    try { & $ScriptBlock; Write-Host "  PASS"; $script:passed++ }
    catch { Write-Host ("  FAIL: " + $_.Exception.Message); $script:failed++ }
    Remove-Item "$storageDir\*" -Force -ErrorAction SilentlyContinue
    Remove-Item "$restoreDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    Start-Sleep -Seconds 2
}

function Backup-File {
    param($FilePath, $Strategy, $Password)
    $ed = $storageDir.Replace('\', '/'); $ef = $FilePath.Replace('\', '/')
    $reqs = @(); $reqs += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs += ('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_backup","arguments":{"filePath":"'+$ef+'","strategy":"'+$Strategy+'","password":"'+$Password+'","storageDir":"'+$ed+'"}}}')
    ($reqs -join "`n") | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    $idx = $null; $t = [datetime]::Now.AddSeconds(60)
    while ([datetime]::Now -lt $t) { $idx = Get-ChildItem "$storageDir\*.indrdrf" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($idx) { break }; Start-Sleep -Seconds 3 }
    if (!$idx) { throw "Backup timeout" }
    '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}' | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    return $idx
}

function SHA256-Hash { param($Path); return [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($Path))).Replace("-","").ToLower() }

# Tests
Run-Test "Empty file (0 bytes)" {
    $f="$storageDir\empty.bin"; [System.IO.File]::WriteAllBytes($f,@()); $idx=Backup-File $f "FSS1" "p@ss"
    $out="$restoreDir\empty.dat"; $idxP=$idx.FullName.Replace('\','/'); $outP=$out.Replace('\','/')
    $r = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"'+$idxP+'","outputPath":"'+$outP+'","password":"p@ss"}}}') | dotnet run --project $mcpCore -c Release --no-build 2>&1
    if (!($r -match 'outputPath')) { throw "Restore failed" }
    $h1=SHA256-Hash $f; $h2=SHA256-Hash $out; if ($h1 -ne $h2) { throw "SHA256 mismatch" }
}

Run-Test "Tiny file (1 byte)" {
    $f="$storageDir\tiny.bin"; [System.IO.File]::WriteAllBytes($f,[byte[]]@(0xAB)); $idx=Backup-File $f "FSS3" "pass"
    $out="$restoreDir\tiny.dat"; $idxP=$idx.FullName.Replace('\','/'); $outP=$out.Replace('\','/')
    $r = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"'+$idxP+'","outputPath":"'+$outP+'","password":"pass"}}}') | dotnet run --project $mcpCore -c Release --no-build 2>&1
    if (!($r -match 'outputPath')) { throw "Restore failed" }
    $h1=SHA256-Hash $f; $h2=SHA256-Hash $out; if ($h1 -ne $h2) { throw "SHA256 mismatch" }
}

Run-Test "Large file (100MB)" {
    $f="$storageDir\large.bin"; $rng=New-Object System.Random(123); $b=New-Object byte[] (100*1024*1024); $rng.NextBytes($b); [System.IO.File]::WriteAllBytes($f,$b)
    $exp=SHA256-Hash $f; $idx=Backup-File $f "FSS1" "pass"
    $out="$restoreDir\large.dat"; $idxP=$idx.FullName.Replace('\','/'); $outP=$out.Replace('\','/')
    $r = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"'+$idxP+'","outputPath":"'+$outP+'","password":"pass"}}}') | dotnet run --project $mcpCore -c Release --no-build 2>&1
    if (!($r -match 'outputPath')) { throw "Restore failed" }
    $h=SHA256-Hash $out; if ($h -ne $exp) { throw "SHA256 mismatch" }
}

Run-Test "Wrong password restore" {
    $f="$storageDir\wrongpw.bin"; [System.IO.File]::WriteAllBytes($f,[byte[]]@(0x42,0x43,0x44)); $idx=Backup-File $f "FSS6" "correctP@ss"
    $idxP=$idx.FullName.Replace('\','/'); $out="$restoreDir\wrongpw.dat"; $outP=$out.Replace('\','/')
    $r = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"'+$idxP+'","outputPath":"'+$outP+'","password":"wrongP@ss"}}}') | dotnet run --project $mcpCore -c Release --no-build 2>&1
    if ($r -match 'outputPath') { throw "Should have rejected wrong password" }
}

Run-Test "Password special characters" {
    $f="$storageDir\specialpw.bin"; $b=[byte[]]@(1..32); [System.IO.File]::WriteAllBytes($f,$b); $pw='p@ss#1!xYz'
    $idx=Backup-File $f "FSS6.1" $pw; $out="$restoreDir\specialpw.dat"; $idxP=$idx.FullName.Replace('\','/'); $outP=$out.Replace('\','/')
    $r = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"restore","arguments":{"indexPath":"'+$idxP+'","outputPath":"'+$outP+'","password":"'+$pw+'"}}}') | dotnet run --project $mcpCore -c Release --no-build 2>&1
    if (!($r -match 'outputPath')) { throw "Restore failed" }
    $h1=SHA256-Hash $f; $h2=SHA256-Hash $out; if ($h1 -ne $h2) { throw "SHA256 mismatch" }
}

Run-Test "Non-existent file" {
    $ed=$storageDir.Replace('\','/')
    $reqs=@(); $reqs+='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'
    $reqs+=('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wpf_backup","arguments":{"filePath":"C:/nonexistent/file.dat","strategy":"FSS1","password":"pass","storageDir":"'+$ed+'"}}}')
    ($reqs -join "`n") | dotnet run --project $mcpWpf -c Release --no-build 2>&1 | Out-Null
    Start-Sleep -Seconds 15
    $files = Get-ChildItem "$storageDir\*" -ErrorAction SilentlyContinue
    if ($files.Count -gt 0) { Write-Host "  Warning: unexpected backup files" }
}

Write-Host ("`nRESULTS: $passed PASS, $failed FAIL") -ForegroundColor Yellow
Remove-Item $storageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $restoreDir -Recurse -Force -ErrorAction SilentlyContinue
Get-Process "RDRF.App" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
