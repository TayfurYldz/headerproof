.PHONY: compile install test uninstall

compile:
	python3 -m py_compile header_active_scan.py file_safety.py

test: compile
	PYTHONPATH=. python3 -m pytest -q

install:
	./install.sh

uninstall:
	./uninstall.sh
