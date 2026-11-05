#!/usr/bin/env bash
# Phantom Grid practice lab — one-command setup (macOS / Linux / WSL2)
#
#   bash setup.sh
#   bash setup.sh --privileged
#   bash setup.sh --skip-build
#
# Safe to re-run. Starts SENTINEL-01, EDGE-02, and OPS-03.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PRIVILEGED=0
SKIP_BUILD=0
ENGINE_WAIT=180
while [ $# -gt 0 ]; do
  case "$1" in
    --privileged) PRIVILEGED=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1"; exit 1 ;;
  esac
  shift
done

if [ -t 1 ]; then C='\033[36m'; G='\033[32m'; Y='\033[33m'; R='\033[31m'; N='\033[0m'
else C=''; G=''; Y=''; R=''; N=''; fi
step() { printf "\n${C}==> %s${N}\n" "$1"; }
good() { printf "    ${G}OK  %s${N}\n" "$1"; }
warn() { printf "    ${Y}!   %s${N}\n" "$1"; }
die()  { printf "\n${R}STOP: %s${N}\n" "$1"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"
case "$OS" in
  Darwin)                 PLATFORM=mac ;;
  Linux)                  if grep -qi microsoft /proc/version 2>/dev/null; then PLATFORM=wsl; else PLATFORM=linux; fi ;;
  MINGW*|MSYS*|CYGWIN*)   PLATFORM=windows ;;
  *)                      PLATFORM=other ;;
esac

if [ "$PLATFORM" = windows ]; then
  echo
  warn "This is Git Bash. PowerShell is the supported path:"
  warn "    powershell -ExecutionPolicy Bypass -File setup.ps1"
  echo
fi

echo
echo "  PHANTOM GRID practice lab"
echo "  SENTINEL-01, EDGE-02, OPS-03  (10.80.40.11-13)"
echo "  ------------------------------------------------"
echo "  platform: $PLATFORM"

step "Checking for Docker"
if ! have docker; then
  warn "Docker is not installed."
  case "$PLATFORM" in
    mac)
      if have brew; then
        printf "    Install Docker Desktop with Homebrew now? (y/N) "
        read -r a </dev/tty || a=n
        case "$a" in
          y|Y|yes|YES)
            brew install --cask docker || die "brew install failed"
            warn "Open Docker Desktop once so it can finish setup, then re-run this script."
            exit 0 ;;
          *) die "Install Docker Desktop, then re-run." ;;
        esac
      else
        die "Install Docker Desktop, then re-run."
      fi ;;
    linux|wsl)
      echo "    Install Docker Engine, for example:"
      echo "        curl -fsSL https://get.docker.com | sudo sh"
      echo "        sudo usermod -aG docker \$USER"
      die "Docker is not installed." ;;
    *) die "Install Docker Desktop, then re-run." ;;
  esac
fi
good "$(docker --version)"

step "Checking the Docker engine"
engine_up() { docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; }

if ! engine_up; then
  warn "Engine is not responding."
  case "$PLATFORM" in
    mac)
      if [ -d "/Applications/Docker.app" ]; then
        echo "    Starting Docker Desktop..."
        open -a Docker || true
      fi ;;
    linux)
      if have systemctl; then
        echo "    Trying: sudo systemctl start docker"
        sudo systemctl start docker 2>/dev/null || warn "could not start the docker service"
      fi ;;
    wsl)
      warn "Start Docker Desktop on Windows with WSL integration enabled." ;;
    windows)
      dd="/c/Program Files/Docker/Docker/Docker Desktop.exe"
      if [ -f "$dd" ]; then
        echo "    Starting Docker Desktop..."
        "$dd" >/dev/null 2>&1 &
      fi ;;
  esac
  echo "    Waiting for the engine (up to ${ENGINE_WAIT}s)."
  deadline=$(( $(date +%s) + ENGINE_WAIT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 3
    if engine_up; then break; fi
    printf "."
  done
  echo
fi

if ! engine_up; then
  die "Docker engine never came up. Start Docker, then re-run."
fi
good "engine $(docker info --format '{{.ServerVersion}}')"

step "Checking Docker Compose"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."
good "$(docker compose version | head -1)"

step "Checking Python 3"
if have python3; then
  good "$(python3 --version 2>&1)"
else
  warn "python3 was not found. The hosts still start, but status needs Python 3."
fi

COMPOSE_ARGS=(-f compose/docker-compose.yml)
[ "$PRIVILEGED" -eq 1 ] && COMPOSE_ARGS+=(-f compose/docker-compose.privileged.yml)

if [ "$SKIP_BUILD" -eq 0 ]; then
  step "Building the lab images (the first run takes a few minutes)"
  docker build -t shadowwatch/base:latest -f images/base/Dockerfile . \
    || die "base image build failed"
  docker compose "${COMPOSE_ARGS[@]}" build \
    || die "host image build failed"
  good "images built"
fi

step "Starting SENTINEL-01, EDGE-02, and OPS-03"
if ! docker compose "${COMPOSE_ARGS[@]}" up -d --remove-orphans; then
  warn "Startup failed. If it mentions systemd or cgroups, re-run:"
  warn "    bash setup.sh --privileged --skip-build"
  die "the lab did not start"
fi

if have python3; then
  python3 verifier/status.py --wait 45 || die "detection check did not pass"
else
  warn "skipping the detection check (needs python3)"
fi

cat <<'NEXT'

  ================================================
  Lab is up.
  ================================================

  Map:          docs/TOPOLOGY.md
  Console:      http://127.0.0.1:8080
                user operator, password c0n$0le

  SSH (password 0per@t0r):
      ssh -p 2211 operator@127.0.0.1    # SENTINEL-01  10.80.40.11
      ssh -p 2212 operator@127.0.0.1    # EDGE-02      10.80.40.12
      ssh -p 2213 operator@127.0.0.1    # OPS-03       10.80.40.13

  Scanner:      D:\Python\Shadow-Watch-Tool
                answer n at preflight, then 127.0.0.1 port 2211, 2212, or 2213
                or swap in hosts.practice.txt for the session
  Check:        make status
  Shut down:    make down

NEXT
