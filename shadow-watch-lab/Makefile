# Phantom Grid practice lab (Linux / macOS / WSL2).
# Windows: use lab.ps1.

COMPOSE := docker compose -f compose/docker-compose.yml
PRIV    := -f compose/docker-compose.privileged.yml
HOSTS   := sw-sentinel-01 sw-edge-02 sw-ops-03

.PHONY: build up up-privileged down reset status selftest verify shell logs

build:
	docker build -t shadowwatch/base:latest -f images/base/Dockerfile .
	$(COMPOSE) build

up:
	$(COMPOSE) up -d --remove-orphans
	python3 verifier/status.py --wait 45

up-privileged:
	$(COMPOSE) $(PRIV) up -d --remove-orphans
	python3 verifier/status.py --wait 45

down:
	$(COMPOSE) down --remove-orphans

reset:
	$(COMPOSE) down --remove-orphans
	$(COMPOSE) up -d --remove-orphans
	python3 verifier/status.py --wait 45

status:
	$(COMPOSE) ps
	python3 verifier/status.py

selftest:
	@for c in $(HOSTS); do echo "== $$c =="; docker exec $$c bash /opt/sw-selftest/parity.sh || true; done

verify:
	python3 verifier/status.py

shell:
	docker exec -it $(filter-out shell,$(MAKECMDGOALS)) bash -l

logs:
	docker exec -it $(filter-out logs,$(MAKECMDGOALS)) journalctl -f --no-pager

%:
	@:
