# PowerShell сборщик пакетов DeviateProxy для Windows
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$Root = Split-Path -Parent $PSScriptRoot
$Src = Join-Path $Root "src"
$Common = Join-Path $Src "common"
$Dist = Join-Path $Root "dist"
$Unpacked = Join-Path $Dist "unpacked"
$Targets = @("firefox", "chrome", "edge")

if (Test-Path $Dist) {
    Remove-Item -Path $Dist -Recurse -Force
}
New-Item -ItemType Directory -Path $Dist -Force | Out-Null

$manifestFx = Get-Content (Join-Path $Src "firefox\manifest.json") -Raw | ConvertFrom-Json
$version = $manifestFx.version

Write-Host "=== Сборка DeviateProxy v$version (PowerShell) ===" -ForegroundColor Cyan

foreach ($target in $Targets) {
    $outDir = Join-Path $Unpacked $target
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    # 1. Common files
    Copy-Item -Path "$Common\*" -Destination $outDir -Recurse -Force

    # 2. Browser-specific files
    $targetSrc = Join-Path $Src $target
    Copy-Item -Path "$targetSrc\*" -Destination $outDir -Recurse -Force

    # 3. License
    $licenseFile = Join-Path $Root "LICENSE"
    if (Test-Path $licenseFile) {
        Copy-Item -Path $licenseFile -Destination $outDir -Force
    }

    $zipPath = Join-Path $Dist "deviateproxy-$target-$version.zip"
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

    $fileCount = (Get-ChildItem -Path $outDir -Recurse -File).Count
    $sizeKb = [math]::Round((Get-Item $zipPath).Length / 1024, 1)

    Write-Host "[$target]" -ForegroundColor Green
    Write-Host "  Unpacked: $outDir"
    Write-Host "  Archive:  $(Split-Path $zipPath -Leaf) ($fileCount файлов, $sizeKb KB)"

    if ($target -eq "firefox") {
        $xpiPath = Join-Path $Dist "deviateproxy-firefox-$version.xpi"
        Copy-Item -Path $zipPath -Destination $xpiPath -Force
        Write-Host "  Firefox:  $(Split-Path $xpiPath -Leaf) (.xpi пакет)"
    }
}

Write-Host "`nВсе пакеты успешно собраны в: $Dist" -ForegroundColor Cyan
