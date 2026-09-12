# PowerShell сборщик пакетов DeviateProxy для Windows
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$Root = Split-Path -Parent $PSScriptRoot
$Src = Join-Path $Root "src"
$Common = Join-Path $Src "common"
$Dist = Join-Path $Root "dist"
$Unpacked = Join-Path $Dist "unpacked"
$Targets = @("firefox", "chrome")
$SkipNames = @(".DS_Store", "Thumbs.db")
$TargetExclude = @{
    "firefox" = @("generate-pac.js")
    "chrome"  = @()
}

function Copy-TreeFiltered($from, $to, $excludeNames = @()) {
    Get-ChildItem -Path $from -Recurse -File | ForEach-Object {
        if ($SkipNames -contains $_.Name -or $excludeNames -contains $_.Name) { return }
        $rel = $_.FullName.Substring($from.Length).TrimStart("\", "/")
        $dest = Join-Path $to $rel
        $destDir = Split-Path $dest -Parent
        if (!(Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Copy-Item -Path $_.FullName -Destination $dest -Force
    }
}

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

    Copy-TreeFiltered $Common $outDir $TargetExclude[$target]
    $targetSrc = Join-Path $Src $target
    if (!(Test-Path $targetSrc)) {
        throw "Папка $targetSrc не найдена"
    }
    Copy-TreeFiltered $targetSrc $outDir

    $licenseFile = Join-Path $Root "LICENSE"
    if (Test-Path $licenseFile) {
        Copy-Item -Path $licenseFile -Destination $outDir -Force
    }

    $manifest = Join-Path $outDir "manifest.json"
    if (!(Test-Path $manifest)) {
        throw "Ошибка: manifest.json отсутствует в $outDir"
    }

    $zipPath = Join-Path $Dist "deviateproxy-$target-$version.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    $hasManifest = $zip.Entries | Where-Object { $_.FullName -eq "manifest.json" }
    $zip.Dispose()
    if (-not $hasManifest) {
        throw "$(Split-Path $zipPath -Leaf): manifest.json должен быть в корне архива"
    }

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
