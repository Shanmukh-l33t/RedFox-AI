# Install the scanner binaries RedFox adapters use into tools\bin (Windows).
# Linux/macOS: use scripts/install-tools.sh.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$bin = Join-Path $root "tools\bin"
$tmp = Join-Path $env:TEMP ("redfox-tools-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $bin, $tmp | Out-Null

function Install-ZipTool {
    param([string]$Name, [string]$Repo)

    $headers = @{ "User-Agent" = "redfox-installer" }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    $asset = $release.assets | Where-Object { $_.name -match "windows_amd64\.zip$" } | Select-Object -First 1
    if (-not $asset) { Write-Host "!! no windows_amd64 asset for $Name"; return }

    $zip = Join-Path $tmp "$Name.zip"
    Write-Host "-> $Name  $($asset.browser_download_url)"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
    $dest = Join-Path $tmp $Name
    Expand-Archive -Path $zip -DestinationPath $dest -Force
    Get-ChildItem -Path $dest -Filter "$Name.exe" -Recurse | Select-Object -First 1 |
        Copy-Item -Destination (Join-Path $bin "$Name.exe") -Force
}

Install-ZipTool -Name "nuclei"    -Repo "projectdiscovery/nuclei"
Install-ZipTool -Name "httpx"     -Repo "projectdiscovery/httpx"
Install-ZipTool -Name "subfinder" -Repo "projectdiscovery/subfinder"
Install-ZipTool -Name "ffuf"      -Repo "ffuf/ffuf"

if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host "!! nmap is not on PATH. Install it from https://nmap.org/download.html"
}

Remove-Item -Recurse -Force $tmp
Write-Host ""
Write-Host "Installed into $bin:"
Get-ChildItem $bin | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host ""
Write-Host "Run 'tools\bin\nuclei.exe -update-templates' once, then 'redfox tools'."