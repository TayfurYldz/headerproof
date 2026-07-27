.PHONY: build compile install lint smoke test uninstall

compile:
	python3 -m compileall -q header_active_scan.py src/headerproof

lint:
	python3 -m ruff check header_active_scan.py src/headerproof tests
	python3 -m mypy

test: compile lint
	PYTHONPATH=. python3 -m pytest -q

build: test
	python3 -m build

smoke:
	python3 tests/release_smoke.py

install:
	./install.sh

uninstall:
	./uninstall.sh
