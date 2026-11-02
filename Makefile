# ShadowTrace developer entry points.
#
# Targets that need a browser, Docker or the network are marked in the help text;
# every target that can run offline is part of `make verify`.

PY ?= python3
BACKEND := backend
FRONTEND := frontend
LAB_PORT ?= 8099
API_PORT ?= 8000

.PHONY: help install verify test test-backend test-frontend coverage lint typecheck \
        security egress lab lab-stop demo-seed smoke evaluate e2e e2e-api clean zip

help:  ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Install backend and frontend dependencies
	$(PY) -m pip install -r requirements.txt -r requirements-dev.txt
	cd $(FRONTEND) && npm ci

verify: egress lint typecheck security test  ## Everything that runs offline (CI gate)

test: test-backend test-frontend  ## Run all test suites

test-backend:  ## Backend tests, with coverage and JUnit evidence in docs/evidence
	cd $(BACKEND) && ST_ENV=test $(PY) -m pytest tests -q --cov=app --cov-branch \
		--cov-report=xml:../docs/evidence/coverage.xml \
		--cov-report=json:../docs/evidence/coverage.json \
		--cov-report=term:skip-covered \
		--cov-fail-under=80 \
		--junitxml=../docs/evidence/junit.xml

test-frontend:  ## Frontend unit tests
	cd $(FRONTEND) && npx vitest run

coverage:  ## Backend coverage report (writes coverage.xml and a text summary)
	cd $(BACKEND) && ST_ENV=test $(PY) -m pytest tests -q \
		--cov=app --cov-report=term-missing --cov-report=xml:../docs/evidence/coverage.xml

lint:  ## Ruff + Windows entry points + tsc and ESLint (react-hooks)
	cd $(BACKEND) && $(PY) -m ruff check app tests ../scripts ../lab
	$(PY) scripts/check_windows_scripts.py
	cd $(FRONTEND) && npm run lint

typecheck:  ## mypy over the backend package
	cd $(BACKEND) && $(PY) -m mypy app --ignore-missing-imports

security:  ## Bandit + pip-audit (network needed for pip-audit)
	$(PY) -m bandit -q -r $(BACKEND)/app -x $(BACKEND)/tests
	$(PY) -m pip_audit -r requirements.txt

egress:  ## Fail if anything in the backend can make HTTP outside SafeHttpClient
	@hits=$$(grep -rnE --include='*.py' \
		"(^|[^A-Za-z0-9_.])(import[[:space:]]+(requests|httpx|aiohttp|urllib3|http\.client|urllib\.request)\\b|from[[:space:]]+(requests|httpx|aiohttp|urllib3|http\.client|urllib\.request)[[:space:]]+import|(requests|httpx|aiohttp|urllib3)\\.[A-Za-z_]+[[:space:]]*\\()" \
		$(BACKEND)/app | grep -v "app/engine/safe_http.py" || true); \
	if [ -n "$$hits" ]; then echo "$$hits"; echo "outbound HTTP outside SafeHttpClient"; exit 1; fi; \
	echo "egress policy: only SafeHttpClient performs network I/O"

lab:  ## Start the isolated lab target on port $(LAB_PORT)
	$(PY) lab/app/lab.py --port $(LAB_PORT)

demo-seed:  ## Create the least-privilege demo account and lab target (prints credentials)
	ST_ENV=test $(PY) scripts/seed_demo.py

smoke:  ## Run one real scan against a running lab and print the scan id
	rm -f /tmp/st_smoke.db*
	ST_ENV=test ST_DATABASE_PATH=/tmp/st_smoke.db \
	ST_PRIVATE_ALLOWLIST=127.0.0.1:$(LAB_PORT) $(PY) scripts/smoke_scan.py

evaluate:  ## Score a scan against the lab ground truth (SCAN_ID=..., strict gate)
	ST_ENV=test ST_DATABASE_PATH=/tmp/st_smoke.db $(PY) scripts/evaluate.py --scan-id $(SCAN_ID) --strict

e2e:  ## Playwright journeys (needs `npm run e2e:install` once, and a built bundle)
	cd $(FRONTEND) && npm run build && npx playwright test

e2e-api:  ## Full lab workflow through the real API + worker (starts its own lab, temp DB)
	ST_ENV=test $(PY) scripts/e2e_round8.py

reset-password:  ## Offline administrator recovery (EMAIL=..., prompts; DATABASE=path optional)
	cd $(BACKEND) && $(PY) -m app.cli reset-password --email $(EMAIL) $(if $(DATABASE),--database $(DATABASE),)

clean:  ## Remove build artefacts and caches
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules/.vite
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

zip:  ## Build the deliverable archive (source-only; no data/, logs/, secrets, build artefacts)
	cd .. && rm -f shadowtrace.zip && zip -rq shadowtrace.zip shadowtrace \
		-x '*/node_modules/*' -x '*/__pycache__/*' -x '*/.pytest_cache/*' \
		-x '*/.mypy_cache/*' -x '*/.ruff_cache/*' -x '*/.venv/*' -x '*/.git/*' \
		-x '*/dist/*' -x 'frontend/dist/*' -x '*/test-results/*' -x '*/playwright-report/*' \
		-x '*/.coverage' -x '.coverage' -x '*/.coverage.*' \
		-x '*.db' -x '*.db-*' -x '*.sqlite3' -x '*.pyc' -x '*.log' -x '*.zip' \
		-x '*.pid' -x 'data/start_epoch.txt' -x 'data/pid_query.txt' \
		-x 'data/secret.key' -x 'data/users.txt' -x 'data/*.db' -x 'logs/*' \
		-x '*.bak' -x '*.orig'
	@if unzip -l ../shadowtrace.zip | grep -qE '(\.coverage|frontend/dist/)'; then \
		echo "archive contains build artefacts"; exit 1; fi
	ls -lh ../shadowtrace.zip
	@echo "shadowtrace.zip built from $(CURDIR) ($(shell unzip -l ../shadowtrace.zip | tail -1 | awk '{print $$2}') files)"
