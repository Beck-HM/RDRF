param(
  [string]$Version = "1.0.0",
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$targets = @{
  "win-x64-cli"  = "F:\RDRF\RDRF-Windows\cli"
  "win-x64-app"  = "F:\RDRF\RDRF-Windows"
  "linux-x64"    = "F:\RDRF\RDRF-LORM\linux-x64\cli"
  "osx-x64"      = "F:\RDRF\RDRF-LORM\osx-x64\cli"
  "osx-arm64"    = "F:\RDRF\RDRF-LORM\osx-arm64\cli"
}

Write-Host "=== RDRF Release Build $Version ===" -ForegroundColor Cyan

# === Step 1: Update version in all .csproj files ===
Write-Host "[1/6] Updating version to $Version..." -ForegroundColor Yellow
$csprojFiles = @(
  "$root\src\RDRF.Core\RDRF.Core.csproj",
  "$root\src\RDRF.Cli\RDRF.Cli.csproj",
  "$root\src\RDRF.App\RDRF.App.csproj",
  "$root\tools\RDRF.Plugins.Path\RDRF.Plugins.Path.csproj",
  "$root\tools\RDRF.Plugins.Rest\RDRF.Plugins.Rest.csproj"
)
foreach ($f in $csprojFiles) {
  $content = Get-Content $f -Raw
  $content = $content -replace '<Version>.*?</Version>', "<Version>$Version</Version>"
  Set-Content $f $content
}
Write-Host "       Version updated." -ForegroundColor Green

# === Step 2: Build + Tests ===
if (-not $SkipTests) {
  Write-Host "[2/6] Building and running tests..." -ForegroundColor Yellow
  dotnet build "$root\RDRF.sln" -c Release --nologo
  if ($LASTEXITCODE -ne 0) { throw "Build failed" }

  dotnet test "$root\tests\RDRF.Core.Tests" -c Release --no-build --nologo
  if ($LASTEXITCODE -ne 0) { throw "Core tests failed" }

  dotnet test "$root\tests\RDRF.Cli.Tests" -c Release --no-build --nologo
  if ($LASTEXITCODE -ne 0) { throw "CLI tests failed" }
} else {
  Write-Host "[2/6] Skipping tests (building only)..." -ForegroundColor Yellow
  dotnet build "$root\RDRF.sln" -c Release --nologo
  if ($LASTEXITCODE -ne 0) { throw "Build failed" }
}
Write-Host "       Build OK." -ForegroundColor Green

# === Step 3: Fix plugin namespace + build ===
Write-Host "[3/6] Building plugins..." -ForegroundColor Yellow
$pluginDirs = @("$root\tools\RDRF.Plugins.Path", "$root\tools\RDRF.Plugins.Rest")
foreach ($dir in $pluginDirs) {
  Get-ChildItem "$dir\*.cs" -Recurse | Where-Object { $_.FullName -notmatch '\\obj\\' } | ForEach-Object {
    $c = Get-Content $_.FullName -Raw
    if ($c -match 'using RDRF\.Dssa;') {
      $c = $c -replace 'using RDRF\.Dssa;', 'using RDRF.Core.Dssa;'
      Set-Content $_.FullName $c
    }
  }
  dotnet build $dir -c Release --nologo
  if ($LASTEXITCODE -ne 0) { throw "Plugin build failed: $dir" }
}
Write-Host "       Plugins OK." -ForegroundColor Green

# === Step 4: Create output directories ===
Write-Host "[4/6] Preparing output directories..." -ForegroundColor Yellow
foreach ($path in $targets.Values) {
  New-Item -ItemType Directory -Force -Path $path | Out-Null
}
New-Item -ItemType Directory -Force -Path "$($targets['win-x64-cli'])\plugins" | Out-Null
foreach ($rid in @("linux-x64", "osx-x64", "osx-arm64")) {
  New-Item -ItemType Directory -Force -Path "$($targets[$rid])\plugins" | Out-Null
}

# === Step 5: Publish CLI targets ===
Write-Host "[5/6] Publishing CLI targets..." -ForegroundColor Yellow
$cliTargets = @{ "win-x64" = "win-x64-cli"; "linux-x64" = "linux-x64"; "osx-x64" = "osx-x64"; "osx-arm64" = "osx-arm64" }
foreach ($entry in $cliTargets.GetEnumerator()) {
  $rid = $entry.Key; $out = $targets[$entry.Value]
  Write-Host "       Publishing $rid -> $out" -ForegroundColor Gray
  dotnet publish "$root\src\RDRF.Cli" -c Release -o $out --self-contained true -r $rid --nologo
  if ($LASTEXITCODE -ne 0) { throw "Publish failed for $rid" }
  Copy-Item "$root\tools\RDRF.Plugins.Path\bin\Release\net8.0\RDRF.Plugins.Path.dll" "$out\plugins\" -Force
  Copy-Item "$root\tools\RDRF.Plugins.Rest\bin\Release\net8.0\RDRF.Plugins.Rest.dll" "$out\plugins\" -Force
  Copy-Item "$root\rdrf.ico" "$out\" -Force
}

# === Step 6: Publish WPF (Windows only, single-file) ===
Write-Host "[6/6] Publishing WPF app (single-file)..." -ForegroundColor Yellow
$wpfOut = $targets["win-x64-app"]
Remove-Item "$wpfOut\*" -Recurse -Force -ErrorAction SilentlyContinue
dotnet publish "$root\src\RDRF.App" -c Release -o $wpfOut --self-contained true -r win-x64 --nologo `
  /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
if ($LASTEXITCODE -ne 0) { throw "WPF publish failed" }
# Remove debug symbols and xml from release output
Remove-Item "$wpfOut\*.pdb" -Force -ErrorAction SilentlyContinue
Remove-Item "$wpfOut\*.xml" -Force -ErrorAction SilentlyContinue
Write-Host "       WPF OK (single-file: $((Get-Item "$wpfOut\RDRF.App.exe").Length / 1MB) MB)." -ForegroundColor Green

# === Step 7: Package LORM tar.gz ===
Write-Host "[7/7] Packaging LORM tar.gz..." -ForegroundColor Yellow
$lormOut = "F:\RDRF\RDRF-LORM"
foreach ($rid in @("linux-x64", "osx-x64", "osx-arm64")) {
  $dir = $targets[$rid]
  $tarname = "rdrf-$Version-$rid.tar.gz"
  $tarPath = "$lormOut\$tarname"
  Write-Host "       $tarname" -ForegroundColor Gray
  tar -czf $tarPath -C (Resolve-Path "$dir\..") (Split-Path $dir -Leaf) 2>&1 | Out-Null
}
Write-Host "       LORM packages OK." -ForegroundColor Green

# === Summary ===
Write-Host "" -ForegroundColor Cyan
Write-Host "=== Build Complete: v$Version ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "RDRF-Windows (x64):" -ForegroundColor White
Write-Host "  WPF (single-file): $($targets['win-x64-app'])" -ForegroundColor Gray
Write-Host "  CLI: $($targets['win-x64-cli'])" -ForegroundColor Gray
Write-Host "RDRF-LORM:" -ForegroundColor White
Write-Host "  Linux:  $lormOut\rdrf-$Version-linux-x64.tar.gz" -ForegroundColor Gray
Write-Host "  macOS intel: $lormOut\rdrf-$Version-osx-x64.tar.gz" -ForegroundColor Gray
Write-Host "  macOS arm:   $lormOut\rdrf-$Version-osx-arm64.tar.gz" -ForegroundColor Gray
Write-Host ""
