# Phantom Grid practice lab — one-command setup (Windows)
#
#   powershell -ExecutionPolicy Bypass -File setup.ps1
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -Privileged -SkipBuild
#
# Safe to re-run. Starts SENTINEL-01, EDGE-02, and OPS-03.

[CmdletBinding()]
param(
    [switch]$Privileged,
    [switch]$SkipBuild,
    [int]$EngineWaitSeconds = 180
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Say  ($m) { Write-Host $m }
function Step ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Good ($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "    !   $m" -ForegroundColor Yellow }
function Die  ($m) { Write-Host "`nSTOP: $m" -ForegroundColor Red; exit 1 }

function Test-Cmd ($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# Windows PowerShell 5.1 turns native stderr into a terminating error when
# $ErrorActionPreference is Stop. Docker writes its progress there.
function Invoke-Native {
    param([scriptblock]$Block)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Block } finally { $ErrorActionPreference = $prev }
}

Say ""
Say "  PHANTOM GRID practice lab"
Say "  SENTINEL-01, EDGE-02, OPS-03  (10.80.40.11-13)"
Say "  ------------------------------------------------"

Step "Checking for Docker"
if (-not (Test-Cmd docker)) {
    Warn "Docker is not installed."
    if (Test-Cmd winget) {
        Say ""
        $a = Read-Host "    Install Docker Desktop now with winget? (y/N)"
        if ($a -match '^(y|yes)$') {
            Say "    Installing. This can take a few minutes and may ask for admin."
            winget install --id Docker.DockerDesktop -e --accept-source-agreements --accept-package-agreements
            Say ""
            Warn "If the installer asked you to sign out or reboot, do that, then re-run this script."
        } else {
            Die "Install Docker Desktop, then re-run: https://www.docker.com/products/docker-desktop/"
        }
    } else {
        Die "Install Docker Desktop, then re-run: https://www.docker.com/products/docker-desktop/"
    }
    if (-not (Test-Cmd docker)) {
        Die "Docker is still not on PATH. Open a new terminal and re-run this script."
    }
}
Good ((docker --version) -join "")

Step "Checking the Docker engine"
$engineUp = $false
try { docker info --format '{{.ServerVersion}}' *> $null; $engineUp = ($LASTEXITCODE -eq 0) } catch { $engineUp = $false }

if (-not $engineUp) {
    Warn "Engine is not responding (Docker Desktop is probably not running)."
    $dd = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($dd) {
        Say "    Starting Docker Desktop..."
        Start-Process -FilePath $dd | Out-Null
    } else {
        Warn "Could not find Docker Desktop.exe. Start it from the Start menu."
    }

    Say "    Waiting for the engine (up to $EngineWaitSeconds s)."
    $deadline = (Get-Date).AddSeconds($EngineWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        try { docker info --format '{{.ServerVersion}}' *> $null; if ($LASTEXITCODE -eq 0) { $engineUp = $true; break } } catch {}
        Write-Host "." -NoNewline
    }
    Say ""
}
if (-not $engineUp) {
    Die "Docker engine never came up. Open Docker Desktop, wait until it is running, then re-run this script."
}
Good ("engine " + ((docker info --format '{{.ServerVersion}}') -join ""))

Step "Checking Python"
$py = $null
foreach ($c in @("python", "python3", "py")) {
    if (Test-Cmd $c) {
        try {
            $v = Invoke-Native { & $c --version 2>&1 }
            if ("$v" -match "Python 3") { $py = $c; break }
        } catch {}
    }
}
if (-not $py) {
    Warn "Python 3 was not found. The hosts still start, but status needs Python 3."
} else {
    Good ((Invoke-Native { & $py --version 2>&1 }) -join "")
}

$labArgs = @()
if ($Privileged) { $labArgs += "-Privileged" }

if (-not $SkipBuild) {
    Step "Building the lab images (the first run takes a few minutes)"
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root "lab.ps1") build
    if ($LASTEXITCODE -ne 0) { Die "Image build failed. Scroll up for the first error." }
    Good "images built"
}

Step "Starting SENTINEL-01, EDGE-02, and OPS-03"
& powershell -ExecutionPolicy Bypass -File (Join-Path $Root "lab.ps1") up @labArgs
if ($LASTEXITCODE -ne 0) {
    Warn "Startup failed. If the error mentions systemd or cgroups, re-run:"
    Warn "    powershell -ExecutionPolicy Bypass -File setup.ps1 -Privileged -SkipBuild"
    Die "the lab did not start"
}

Say ""
Say "  ================================================"
Say "  Lab is up."
Say "  ================================================"
Say ""
Say "  Map:          docs\TOPOLOGY.md"
Say "  Console:      http://127.0.0.1:8080"
Say "                user operator, password c0n`$0le"
Say ""
Say "  SSH (password 0per@t0r):"
Say "      ssh -p 2211 operator@127.0.0.1    # SENTINEL-01  10.80.40.11"
Say "      ssh -p 2212 operator@127.0.0.1    # EDGE-02      10.80.40.12"
Say "      ssh -p 2213 operator@127.0.0.1    # OPS-03       10.80.40.13"
Say ""
Say "  Scanner:      D:\Python\Shadow-Watch-Tool"
Say "                answer n at preflight, then 127.0.0.1 port 2211, 2212, or 2213"
Say "                or swap in hosts.practice.txt for the session"
Say "  Check:        .\lab.ps1 status"
Say "  Shut down:    .\lab.ps1 down"
Say ""
