#!/usr/bin/env bash
# Shadow Watch - one-command setup (macOS / Linux / WSL2)
#
#   1. Unzip this folder anywhere.
#   2. cd into it and run:   bash setup.sh
#
# Safe to re-run. It checks what's missing, fixes what it can, and starts the lab.
#
#   bash setup.sh --minutes 60    set the exercise clock (default 45 minutes)
#   bash setup.sh --privileged    fall back to privileged containers
#   bash setup.sh --skip-build    images already built

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PRIVILEGED=0
SKIP_BUILD=0
MINUTES=0
ENGINE_WAIT=180
while [ $# -gt 0 ]; do
  case "$1" in
    --privileged) PRIVILEGED=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --minutes) shift; MINUTES="${1:-0}" ;;
    --minutes=*) MINUTES="${1#*=}" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  esac
  shift
done

# Exercise clock. Baked into the timer at build time, so a change forces a rebuild.
if [ "${MINUTES:-0}" -gt 0 ] 2>/dev/null; then
  if [ "$MINUTES" -lt 5 ] || [ "$MINUTES" -gt 240 ]; then
    echo "--minutes must be between 5 and 240"; exit 1
  fi
  export EXERCISE_WIPE_AFTER=$(( MINUTES * 60 ))
  SKIP_BUILD=0
fi

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
  warn "You're on Windows (Git Bash/MSYS). This script works, but PowerShell is the"
  warn "supported path and gives better errors:"
  warn "    powershell -ExecutionPolicy Bypass -File setup.ps1"
  echo
fi

echo
echo "  SHADOW WATCH - live incident response lab"
echo "  Six hosts. SENTINEL-01 must stay online."
echo "  ------------------------------------------------"
echo "  platform: $PLATFORM"
if [ "${MINUTES:-0}" -gt 0 ] 2>/dev/null; then
  echo "  exercise clock: $MINUTES minutes (rebuilding sentinel-01)"
else
  echo "  exercise clock: 45 minutes  (change with:  --minutes 60)"
fi

# --- 1. Docker present? ------------------------------------------------------
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
            warn "Now OPEN Docker Desktop once from Applications (it must finish first-run setup), then re-run this script."
            exit 0 ;;
          *) die "Install Docker Desktop, then re-run: https://www.docker.com/products/docker-desktop/" ;;
        esac
      else
        die "Install Docker Desktop, then re-run: https://www.docker.com/products/docker-desktop/"
      fi ;;
    linux|wsl)
      echo
      echo "    Install Docker Engine with your package manager, for example:"
      echo "        curl -fsSL https://get.docker.com | sudo sh"
      echo "        sudo usermod -aG docker \$USER    # then log out and back in"
      die "Docker not installed." ;;
    windows)
      die "Install Docker Desktop, then re-run: https://www.docker.com/products/docker-desktop/" ;;
    *) die "Unsupported platform: $OS" ;;
  esac
fi
good "$(docker --version)"

# --- 2. Engine running? ------------------------------------------------------
step "Checking the Docker engine"
engine_up() { docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; }

if ! engine_up; then
  warn "Engine is not responding."
  case "$PLATFORM" in
    mac)
      if [ -d "/Applications/Docker.app" ]; then
        echo "    Starting Docker Desktop..."
        open -a Docker || true
      else
        warn "Docker Desktop not found in /Applications - start it manually."
      fi ;;
    linux)
      if have systemctl; then
        echo "    Trying: sudo systemctl start docker"
        sudo systemctl start docker 2>/dev/null || warn "could not start the docker service"
      fi ;;
    wsl)
      warn "In WSL2, start Docker Desktop on the Windows side with WSL integration enabled." ;;
    windows)
      dd="/c/Program Files/Docker/Docker/Docker Desktop.exe"
      if [ -f "$dd" ]; then
        echo "    Starting Docker Desktop..."
        "$dd" >/dev/null 2>&1 &
      else
        warn "Start Docker Desktop from the Start menu."
      fi ;;
  esac

  echo "    Waiting for the engine (up to ${ENGINE_WAIT}s). First start is slow."
  deadline=$(( $(date +%s) + ENGINE_WAIT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 3
    if engine_up; then break; fi
    printf "."
  done
  echo
fi

if ! engine_up; then
  if [ "$PLATFORM" = linux ] && ! groups 2>/dev/null | grep -qw docker; then
    warn "You may not be in the 'docker' group. Fix with:"
    warn "    sudo usermod -aG docker \$USER     # then log out and back in"
  fi
  die "Docker engine never came up. Start Docker, wait until it reports running, then re-run."
fi
good "engine $(docker info --format '{{.ServerVersion}}')"

# --- 3. Compose v2 -----------------------------------------------------------
step "Checking Docker Compose"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (try upgrading Docker)."
good "$(docker compose version | head -1)"

# --- 4. Python 3 (verifier; stdlib only) -------------------------------------
step "Checking Python 3"
if have python3; then
  good "$(python3 --version 2>&1)"
else
  warn "python3 not found. The lab runs without it, but 'verify' and 'status' need it."
  case "$PLATFORM" in
    mac)        warn "Install with: brew install python" ;;
    linux|wsl)  warn "Install with: sudo apt install -y python3   (or your distro's equivalent)" ;;
  esac
fi

# --- 5. Build ----------------------------------------------------------------
COMPOSE_ARGS=(-f compose/docker-compose.yml)
[ "$PRIVILEGED" -eq 1 ] && COMPOSE_ARGS+=(-f compose/docker-compose.privileged.yml)

if [ "$SKIP_BUILD" -eq 0 ]; then
  step "Building the lab images (first run takes a few minutes)"
  docker build -t shadowwatch/base:latest -f images/base/Dockerfile . \
    || die "base image build failed"
  if [ "${MINUTES:-0}" -gt 0 ] 2>/dev/null; then
    docker compose "${COMPOSE_ARGS[@]}" build --no-cache sentinel-01 || die "clock rebuild failed"
  fi
  docker compose "${COMPOSE_ARGS[@]}" build \
    || die "host image build failed"
  good "images built"
fi

# --- 6. Up -------------------------------------------------------------------
step "Starting the cluster"
# Deliberately no `rm` of response/ here. setup.sh is safe to re-run, and a
# re-run used to delete the fragments the analyst had already collected --
# `make reset` is the only thing that clears deliverables.
if ! docker compose "${COMPOSE_ARGS[@]}" up -d; then
  warn "Startup failed. If it mentions systemd or cgroups, re-run as:"
  warn "    bash setup.sh --privileged --skip-build"
  die "cluster did not start"
fi

echo "    waiting for mission-control..."
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 http://127.0.0.1:8000 >/dev/null 2>&1; then break; fi
  sleep 2
done

if have python3; then
  python3 verifier/baseline.py || warn "baseline not recorded - run 'make up' once python3 is installed"
else
  warn "skipping baseline (needs python3); the no-restart gate will fail until you record it"
fi

# --- 7. Where to go next -----------------------------------------------------
cat <<'NEXT'

  ================================================
  Lab is up. The exercise clock is running.
  ================================================

  Read first:   docs/RUNBOOK.md
  The advisory: docs/ADVISORY-IOC-2026-114.md

  Get a shell on the jump box:
      docker exec -it sw-analyst bash -l

  Or SSH in (password: analyst):
      ssh -p 2226 analyst@localhost     # analyst jump box
      ssh -p 2224 analyst@localhost     # sentinel-01  (do NOT reboot it)
      ssh -p 2222 analyst@localhost     # relay
      ssh -p 2220 analyst@localhost     # console
      ssh -p 2225 analyst@localhost     # sentinel-02
      ssh -p 2223 analyst@localhost     # mission-control

  Scan it with HARBNGR:  python3 start.py     (127.0.0.1:2224, analyst / analyst)
  Check your standing:   make status     (or python3 verifier/status.py)
  Grade your response:   make verify     (or python3 verifier/verify.py)
  Start over:            make reset
  Shut down:             make down       (or docker compose -f compose/docker-compose.yml down)

  Collect volatile evidence BEFORE you kill anything.

NEXT
