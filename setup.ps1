# Shadow Watch - one-command setup (Windows)
#
#   1. Unzip this folder anywhere.
#   2. Right-click this file -> "Run with PowerShell"
#      (or in a terminal:  powershell -ExecutionPolicy Bypass -File setup.ps1)
#
# Safe to re-run. It checks what's missing, fixes what it can, and starts the lab.

[CmdletBinding()]
param(
    [switch]$Privileged,      # fall back to privileged containers if systemd misbehaves
    [switch]$SkipBuild,       # images already built
    [int]$Minutes = 0,        # exercise clock in minutes (default 45; raise it for a first run)
    [int]$EngineWaitSeconds = 180
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeDirPath = Join-Path $Root "compose"

# Exercise clock. Baked into the timer at build time, so a change forces a rebuild.
if ($Minutes -gt 0) {
    if ($Minutes -lt 5 -or $Minutes -gt 240) { Write-Host "-Minutes must be between 5 and 240" -ForegroundColor Red; exit 1 }
    $env:EXERCISE_WIPE_AFTER = [string]($Minutes * 60)
    $SkipBuild = $false   # the clock lives in the image; it has to be rebuilt
}

function Say  ($m) { Write-Host $m }
function Step ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Good ($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "    !   $m" -ForegroundColor Yellow }
function Die  ($m) { Write-Host "`nSTOP: $m" -ForegroundColor Red; exit 1 }

function Test-Cmd ($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# Windows PowerShell 5.1 turns a native command's stderr into ErrorRecords, so
# with $ErrorActionPreference = "Stop" the FIRST stderr line aborts the script.
# `docker compose build` writes all of its normal progress to stderr, which made
# `setup.ps1 -Minutes N` die on startup before this wrapper existed.
#
# Redirecting the stream does NOT help -- 2>$null and 2>file raise the same
# terminating error in 5.1 -- so the preference itself has to come down for the
# duration of the call. Real cmdlet errors still stop the script.
function Invoke-Native {
    param([scriptblock]$Block)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Block } finally { $ErrorActionPreference = $prev }
}

Say ""
Say "  SHADOW WATCH - live incident response lab"
Say "  Six hosts. SENTINEL-01 must stay online."
Say "  ------------------------------------------------"
if ($Minutes -gt 0) { Say "  exercise clock: $Minutes minutes (rebuilding sentinel-01)" }
else { Say "  exercise clock: 45 minutes  (change with:  -Minutes 60)" }

# --- 1. Docker present? ------------------------------------------------------
Step "Checking for Docker"
if (-not (Test-Cmd docker)) {
    Warn "Docker is not installed."
    if (Test-Cmd winget) {
        Say ""
        $a = Read-Host "    Install Docker Desktop now with winget? (y/N)"
        if ($a -match '^(y|yes)$') {
            Say "    Installing - this takes a few minutes and may ask for admin."
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
        Die "Docker still not on PATH. Open a NEW terminal after install and re-run this script."
    }
}
Good ((docker --version) -join "")

# --- 2. Engine running? ------------------------------------------------------
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
        Warn "Could not find Docker Desktop.exe - start it from the Start menu."
    }

    Say "    Waiting for the engine (up to $EngineWaitSeconds s). First start is slow."
    $deadline = (Get-Date).AddSeconds($EngineWaitSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        try { docker info --format '{{.ServerVersion}}' *> $null; if ($LASTEXITCODE -eq 0) { $engineUp = $true; break } } catch {}
        Write-Host "." -NoNewline
    }
    Say ""
}
if (-not $engineUp) {
    Die "Docker engine never came up. Open Docker Desktop, wait for 'Engine running', then re-run this script."
}
Good ("engine " + ((docker info --format '{{.ServerVersion}}') -join ""))

# --- 3. Python (the verifier needs it; stdlib only) --------------------------
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
    Warn "Python 3 not found. The lab runs without it, but 'verify' and 'status' need it."
    if (Test-Cmd winget) {
        $a = Read-Host "    Install Python 3 with winget? (y/N)"
        if ($a -match '^(y|yes)$') {
            winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements
            Warn "Open a NEW terminal after install so PATH updates, then re-run this script."
        }
    } else {
        Warn "Get it from https://www.python.org/downloads/ (tick 'Add to PATH')."
    }
} else {
    Good ((Invoke-Native { & $py --version 2>&1 }) -join "")
}

# --- 4. Build ----------------------------------------------------------------
$labArgs = @()
if ($Privileged) { $labArgs += "-Privileged" }

if (-not $SkipBuild) {
    Step "Building the lab images (first run takes a few minutes)"
    if ($Minutes -gt 0) {
        # Force the clock layer to rebuild rather than come from cache. Capture
        # the output instead of piping it to the host: docker's progress arrives
        # on stderr, and letting those ErrorRecords reach the console renders
        # them in red, which reads as a failed build when it is not one.
        $buildLog = Invoke-Native { & docker compose -f (Join-Path $ComposeDirPath "docker-compose.yml") build --no-cache sentinel-01 2>&1 }
        if ($LASTEXITCODE -ne 0) {
            $buildLog | Select-Object -Last 5 | ForEach-Object { Warn ("" + $_) }
            Die "Clock rebuild of sentinel-01 failed."
        }
        Good "sentinel-01 rebuilt with a $Minutes-minute clock"
    }
    & powershell -ExecutionPolicy Bypass -File (Join-Path $Root "lab.ps1") build
    if ($LASTEXITCODE -ne 0) { Die "Image build failed. Scroll up for the first error." }
    Good "images built"
}

# --- 5. Up -------------------------------------------------------------------
Step "Starting the cluster"
& powershell -ExecutionPolicy Bypass -File (Join-Path $Root "lab.ps1") up @labArgs
if ($LASTEXITCODE -ne 0) {
    Warn "Startup failed. If it mentions systemd or cgroups, re-run as:"
    Warn "    powershell -ExecutionPolicy Bypass -File setup.ps1 -Privileged -SkipBuild"
    Die "cluster did not start"
}

# --- 6. Where to go next -----------------------------------------------------
Say ""
Say "  ================================================"
Say "  Lab is up. The exercise clock is running."
Say "  ================================================"
Say ""
Say "  Read first:   docs\RUNBOOK.md"
Say "  The advisory: docs\ADVISORY-IOC-2026-114.md"
Say ""
Say "  Get a shell on the jump box:"
Say "      .\lab.ps1 shell analyst"
Say ""
Say "  Or SSH in (password: analyst):"
Say "      ssh -p 2226 analyst@localhost     # analyst jump box"
Say "      ssh -p 2224 analyst@localhost     # sentinel-01  (do NOT reboot it)"
Say "      ssh -p 2222 analyst@localhost     # relay"
Say "      ssh -p 2220 analyst@localhost     # console"
Say "      ssh -p 2225 analyst@localhost     # sentinel-02"
Say "      ssh -p 2223 analyst@localhost     # mission-control"
Say ""
Say "  Scan it with HARBNGR:  python start.py     (127.0.0.1:2224, analyst / analyst)"
Say "  Check your standing:   .\lab.ps1 status"
Say "  Grade your response:   .\lab.ps1 verify"
Say "  Start over:            .\lab.ps1 reset"
Say "  Shut down:             .\lab.ps1 down"
Say ""
Say "  Collect volatile evidence BEFORE you kill anything."
Say ""
