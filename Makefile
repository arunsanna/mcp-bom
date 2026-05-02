.PHONY: install test reproduce clean

PYTHON ?= python3
VENV ?= extractor/.venv

install:
	$(PYTHON) -m venv $(VENV)
	. $(VENV)/bin/activate && pip install -e "extractor/.[dev]"

test:
	. $(VENV)/bin/activate && pytest extractor/tests/ -v

reproduce: install
	. $(VENV)/bin/activate && pytest extractor/tests/ -v --tb=short
	. $(VENV)/bin/activate && python extractor/scripts/reproduce.py
	@echo "Reproduction complete — tests pass and fixture scan matches golden."

clean:
	rm -rf $(VENV) extractor/.pytest_cache extractor/tests/__pycache__
	find extractor -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
