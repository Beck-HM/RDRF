# RDRF WPF MCP - Full Strategy Test (single MCP process)
$ErrorActionPreference = "Continue"
$root = "F:\RDRF\RDRF.NET"
$mcp = "$root\tools\RDRF.Mcp.Wpf"
$testFile = "$env:TEMP\rdrf_strategy_test_50mb.dat"
$storageDir = "$env:TEMP\rdrf_test_backups"

# Cleanup previous
Remove-Item "$env:TEMP\rdrf_mcp_test.txt" -Force -ErrorAction SilentlyContinue

Write-Host "=== Creating 10MB test file ===" -ForegroundColor Cyan
$bytes = New-Object byte[] (10 * 1024 * 1024)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[System.IO.File]::WriteAllBytes($testFile, $bytes)
$escapedFile = $testFile.Replace('\', '/')
$escapedDir = $storageDir.Replace('\', '/')

$strategies = @("FSS1", "FSS3", "FSS5", "FSS6", "FSS6.1", "FSS6.2")
$backupResults = @{}

# Build all requests for a single MCP session
$requests = @()

# Launch
$requests += '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wpf_launch","arguments":{}}}'

foreach ($strategy in $strategies) {
    $req = ('{"jsonrpc":"2.0","id":' + (2 + $strategies.IndexOf($strategy)) + ',"method":"tools/call","params":{"name":"wpf_backup","arguments":{"filePath":"' + $escapedFile + '","strategy":"' + $strategy + '","password":"test123","storageDir":"' + $escapedDir + '"}}}')
    $requests += $req
}

# Close at the end
$requests += '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"wpf_close","arguments":{}}}'

Write-Host "Launching MCP server with $($requests.Count) requests..." -ForegroundColor Cyan

# Run all requests through a single MCP server process
$allReqs = $requests -join "`n"
$response = $allReqs | dotnet run --project $mcp -c Release --no-build 2>&1

Write-Host ""
Write-Host "===== RAW RESPONSE =====" -ForegroundColor Cyan
Write-Host $response
Write-Host ""

# Check backup files after all strategies run
Start-Sleep -Seconds 10

Write-Host "===== CHECKING BACKUP FILES =====" -ForegroundColor Yellow
if (Test-Path $storageDir) {
    $fingerprints = Get-ChildItem "$storageDir\*.indrdrf" -ErrorAction SilentlyContinue
    if ($fingerprints.Count -gt 0) {
        Write-Host ("Found " + $fingerprints.Count + " backup(s):") -ForegroundColor Green
        foreach ($f in $fingerprints) {
            $fp = $f.BaseName
            $frags = Get-ChildItem "$storageDir\$fp*" | Measure-Object | Select-Object -ExpandProperty Count
            Write-Host ("  " + $fp.Substring(0, 16) + "... - " + $frags + " file(s)")
        }
    } else {
        Write-Host "No .indrdrf files found" -ForegroundColor Red
        $allFiles = Get-ChildItem $storageDir -ErrorAction SilentlyContinue
        if ($allFiles.Count -gt 0) {
            Write-Host ("Files in storageDir: " + ($allFiles | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ", ")
        } else {
            Write-Host "storageDir is empty" -ForegroundColor Red
        }
    }
} else {
    Write-Host "storageDir does not exist" -ForegroundColor Red
}

# Cleanup
Remove-Item $testFile -Force -ErrorAction SilentlyContinue
Remove-Item "$storageDir\*" -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Done" -ForegroundColor Green
