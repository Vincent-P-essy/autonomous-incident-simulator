.PHONY: validate test quality benchmark demo serve docker-build

PYTHON ?= python3
export PYTHONPATH := src
export PYTHONDONTWRITEBYTECODE := 1

validate:
	@for scenario in examples/*.json; do $(PYTHON) -m incident_simulator validate "$$scenario" >/dev/null || exit 1; done

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

quality: validate
	ruff check src tests scripts
	ruff format --check src tests scripts
	mypy src/incident_simulator
	$(PYTHON) -m compileall -q src tests scripts
	$(PYTHON) scripts/safety_static_gate.py
	$(PYTHON) scripts/quality_gate.py
	$(PYTHON) scripts/verify_golden.py

benchmark:
	$(PYTHON) -m incident_simulator benchmark examples/payroll-no-malware.json --runs 50

demo:
	$(PYTHON) -m incident_simulator simulate examples/payroll-no-malware.json --output-dir out/payroll-no-malware

serve:
	$(PYTHON) -m incident_simulator serve --host 127.0.0.1 --port 8080 --scenario-dir examples

docker-build:
	docker build --tag autonomous-incident-simulator:local .
