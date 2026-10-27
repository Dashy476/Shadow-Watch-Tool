# Shadow Watch lab control surface (Windows / PowerShell).
#
#   lab.ps1 build [host]     build the base image, then all host images
#   lab.ps1 up               start the cluster and record the no-restart baseline
#   lab.ps1 status           hosts, availability, and the wipe countdown
#   lab.ps1 selftest         prove VM parity inside every host
#   lab.ps1 verify           grade the response; print the flag if all gates pass
#   lab.ps1 solve            run the reference response (then `verify`)
#   lab.ps1 shell <host>     an interactive shell in a host
#   lab.ps1 logs <host>      follow a host's systemd journal
#   lab.ps1 down             stop and remove the cluster
#
# Add -Privileged to `up` if systemd misbehaves under fine-grained capabilities.

param(
    [Parameter(Position = 0)][string]$Command = "status",
    [Parameter(Position = 1)][string]$Arg,
    [switch]$Privileged
)

$ErrorActionPreference = "Stop"
$Root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeDir  = Join-Path $Root "compose"
$ComposeFile = Join-Path $ComposeDir "docker-compose.yml"
$PrivFile    = Join-Path $ComposeDir "docker-compose.privileged.yml"

$Hosts = @{
    relay            = "sw-relay"
    console          = "sw-console"
    "mission-control" = "sw-mission-control"
    "sentinel-01"    = "sw-sentinel-01"
    "sentinel-02"    = "sw-sentinel-02"
    analyst          = "sw-analyst"
}
$Containers = $Hosts.Values

function Get-ComposeArgs {
    $a = @("compose", "-f", $ComposeFile)
    if ($Privileged) { $a += @("-f", $PrivFile) }
    return $a
}

function Invoke-Compose {
    $a = Get-ComposeArgs
    & docker @a @args
}

function Build-Lab {
    Write-Host "building base image..." -ForegroundColor Cyan
    & docker build -t shadowwatch/base:latest -f (Join-Path $Root "images\base\Dockerfile") $Root
    if ($LASTEXITCODE -ne 0) { throw "base image build failed" }
    Write-Host "building host images..." -ForegroundColor Cyan
    Invoke-Compose build @(if ($Arg) { $Arg })
    if ($LASTEXITCODE -ne 0) { throw "host image build failed" }
}

# Only `reset` calls this. `up` must NOT: students re-run `up` mid-exercise to
# re-capture the G1 baseline, and wiping their collected fragments as the price
# of that is how a first run quietly loses its evidence.
function Clear-Deliverables {
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Root "response\recovered.txt")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Root "response\report.md")
}

function Save-Baseline {
    $b = @{}
    foreach ($name in $Hosts.Keys) {
        $c = $Hosts[$name]
        $j = & docker inspect $c | ConvertFrom-Json
        $b[($name -replace '-', '_')] = @{
            restart_count = $j[0].RestartCount
            started_at    = $j[0].State.StartedAt
        }
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $Root "flags") | Out-Null
    $b | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $Root "flags\baseline.json")
    Write-Host "baseline recorded (restart forbidden from here on)" -ForegroundColor Green
}

function Show-Status {
    & docker ps --filter "name=sw-" --format "table {{.Names}}\t{{.Status}}"
    Write-Host ""
    try {
        $stats = Invoke-RestMethod -Uri "http://127.0.0.1:8000" -TimeoutSec 5
        Write-Host ("availability : {0:P1}  ({1}/{2} tracks)" -f $stats.availability, $stats.received, $stats.expected)
        Write-Host ("forged tracks: {0}" -f $stats.forged)
        Write-Host ("max gap      : {0}s" -f $stats.max_gap)
        Write-Host ("sectors seen : {0}   missing: {1}" -f ($stats.sectors_seen -join ","), ($stats.missing_sectors -join ","))
    } catch {
        Write-Host "mission-control :8000 not answering yet" -ForegroundColor Yellow
    }
    Write-Host ""
    # 2>$null still raises a terminating error in Windows PowerShell 5.1 when
    # $ErrorActionPreference is "Stop" and the command writes anything to
    # stderr, so `status` would abort instead of reporting. Lower it here only.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & docker exec sw-sentinel-01 systemctl list-timers logrotate-guard.timer --no-pager 2>$null }
    finally { $ErrorActionPreference = $prev }
}

function Invoke-SelfTest {
    foreach ($c in $Containers) {
        Write-Host "== $c ==" -ForegroundColor Cyan
        & docker exec $c bash /opt/sw-selftest/parity.sh
    }
}

function Enter-Shell {
    if (-not $Arg) { throw "usage: lab.ps1 shell <host>   (hosts: $($Hosts.Keys -join ', '))" }
    $c = $Hosts[$Arg]
    if (-not $c) { $c = $Arg }
    & docker exec -it $c bash -l
}

function Show-Logs {
    if (-not $Arg) { throw "usage: lab.ps1 logs <host>" }
    $c = $Hosts[$Arg]; if (-not $c) { $c = $Arg }
    & docker exec -it $c journalctl -f --no-pager
}

switch ($Command.ToLower()) {
    "build"    { Build-Lab }
    "up"       {
        Invoke-Compose up -d
        if ($LASTEXITCODE -ne 0) { throw "compose up failed" }
        Write-Host "waiting for mission-control..." -ForegroundColor Cyan
        for ($i = 0; $i -lt 30; $i++) {
            try { Invoke-RestMethod -Uri "http://127.0.0.1:8000" -TimeoutSec 3 | Out-Null; break }
            catch { Start-Sleep -Seconds 2 }
        }
        Save-Baseline
        Show-Status
    }
    "down"     { Invoke-Compose down }
    "reset"    { Clear-Deliverables; Invoke-Compose down; Invoke-Compose up -d; Save-Baseline }
    "status"   { Show-Status }
    "selftest" { Invoke-SelfTest }
    "verify"   { & python (Join-Path $Root "verifier\verify.py") }
    "solve"    { Write-Host "Not in the student build. Work the incident - hints are on the challenge page." -ForegroundColor Yellow }
    "shell"    { Enter-Shell }
    "logs"     { Show-Logs }
    default    { Write-Host "unknown command '$Command'"; Write-Host "build|up|down|reset|status|selftest|verify|solve|shell|logs" }
}
