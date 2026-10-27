# Shadow Watch lab control surface (Linux / macOS / WSL2).
# Windows users: use lab.ps1 instead.

COMPOSE := docker compose -f compose/docker-compose.yml
PRIV    := -f compose/docker-compose.privileged.yml
HOSTS   := sw-relay sw-console sw-mission-control sw-sentinel-01 sw-sentinel-02 sw-analyst

.PHONY: build up down reset status selftest verify solve shell logs

build:
	docker build -t shadowwatch/base:latest -f images/base/Dockerfile .
	$(COMPOSE) build

# No `rm` of the deliverables here -- only `reset` clears them. `up` gets re-run
# mid-exercise to re-capture the G1 baseline, and it must not eat the analyst's
# collected fragments when it does.
up:
	$(COMPOSE) up -d
	python3 verifier/baseline.py

# Fallback if systemd misbehaves under fine-grained capabilities:
up-privileged:
	$(COMPOSE) $(PRIV) up -d
	python3 verifier/baseline.py

down:
	$(COMPOSE) down

reset:
	@rm -f response/recovered.txt response/report.md
	$(COMPOSE) down
	$(COMPOSE) up -d
	python3 verifier/baseline.py

status:
	$(COMPOSE) ps
	python3 verifier/status.py

selftest:
	@for c in $(HOSTS); do echo "== $$c =="; docker exec $$c bash /opt/sw-selftest/parity.sh || true; done

verify:
	python3 verifier/verify.py

solve:
	@echo "Not in the student build. Work the incident - hints are on the challenge page."

shell:
	docker exec -it $(filter-out shell,$(MAKECMDGOALS)) bash -l

logs:
	docker exec -it $(filter-out logs,$(MAKECMDGOALS)) journalctl -f --no-pager

%:
	@:
