# Phantom Grid practice lab (Windows / PowerShell).
#
#   lab.ps1 build            build the base image, then the three hosts
#   lab.ps1 up               start SENTINEL-01, EDGE-02, and OPS-03
#   lab.ps1 status           containers plus the detection-uptime check
#   lab.ps1 selftest         VM-parity checks inside every host
#   lab.ps1 verify           same check as status (there is no flag grade)
#   lab.ps1 shell <host>     interactive shell
#   lab.ps1 logs <host>      follow a host journal
#   lab.ps1 down             stop and remove the lab
#   lab.ps1 reset            down, then up
#
# Add -Privileged to up or reset if systemd misbehaves.

param(
    [Parameter(Position = 0)][string]$Command = "status",
    [Parameter(Position = 1)][string]$Arg,
    [switch]$Privileged
)

$ErrorActionPreference = "Stop"
$Root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $Root "compose\docker-compose.yml"
$PrivFile    = Join-Path $Root "compose\docker-compose.privileged.yml"

$Hosts = [ordered]@{
    "sentinel-01" = "sw-sentinel-01"
    "edge-02"     = "sw-edge-02"
    "ops-03"      = "sw-ops-03"
}

function Get-ComposeArgs {
    $a = @("compose", "-f", $ComposeFile)
    if ($Privileged) { $a += @("-f", $PrivFile) }
    return $a
}

# PowerShell 5.1 treats docker's stderr progress as a terminating error when
# $ErrorActionPreference is Stop. Drop the preference for the native call.
function Invoke-Docker {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & docker @args }
    finally { $ErrorActionPreference = $prev }
}

function Invoke-Compose {
    $dockerArgs = @(Get-ComposeArgs) + @($args)
    Invoke-Docker @dockerArgs
    if ($LASTEXITCODE -ne 0) { throw "docker compose failed ($LASTEXITCODE)" }
}

function Build-Lab {
    Write-Host "building base image..." -ForegroundColor Cyan
    Invoke-Docker build -t shadowwatch/base:latest -f (Join-Path $Root "images\base\Dockerfile") $Root
    if ($LASTEXITCODE -ne 0) { throw "base image build failed" }
    Write-Host "building host images..." -ForegroundColor Cyan
    if ($Arg) { Invoke-Compose build $Arg } else { Invoke-Compose build }
}

function Show-Status {
    Invoke-Docker ps --filter "name=sw-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    Write-Host ""
    & python (Join-Path $Root "verifier\status.py")
}

function Invoke-SelfTest {
    foreach ($c in $Hosts.Values) {
        Write-Host "== $c ==" -ForegroundColor Cyan
        Invoke-Docker exec $c bash /opt/sw-selftest/parity.sh
    }
}

function Resolve-Host([string]$Name) {
    if (-not $Name) { throw "name a host: $($Hosts.Keys -join ', ')" }
    if ($Hosts.Contains($Name)) { return $Hosts[$Name] }
    return $Name
}

switch ($Command.ToLower()) {
    "build" { Build-Lab }
    "up" {
        Invoke-Compose up -d --remove-orphans
        Write-Host "waiting for detections and log forwarding..." -ForegroundColor Cyan
        & python (Join-Path $Root "verifier\status.py") --wait 45
        if ($LASTEXITCODE -ne 0) { throw "detection check did not pass" }
    }
    "down"  { Invoke-Compose down --remove-orphans }
    "reset" {
        Invoke-Compose down --remove-orphans
        Invoke-Compose up -d --remove-orphans
        & python (Join-Path $Root "verifier\status.py") --wait 45
        if ($LASTEXITCODE -ne 0) { throw "detection check did not pass" }
    }
    "status"   { Show-Status }
    "selftest" { Invoke-SelfTest }
    "verify"   { & python (Join-Path $Root "verifier\status.py"); exit $LASTEXITCODE }
    "shell"    { Invoke-Docker exec -it (Resolve-Host $Arg) bash -l }
    "logs"     { Invoke-Docker exec -it (Resolve-Host $Arg) journalctl -f --no-pager }
    default    { Write-Host "unknown command '$Command'"; Write-Host "build|up|down|reset|status|selftest|verify|shell|logs" }
}
