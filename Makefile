.PHONY: install scan scan-full test coverage lint dashboard clean

install:
	pip install -e ".[dev,dashboard]"

scan:
	viabilityscan scan . --output viability_report.json

scan-full:
	viabilityscan scan . --full --output viability_report.json

scan-ci:
	viabilityscan scan . --ci --output viability_report.json

test:
	pytest tests/ -v

coverage:
	pytest tests/ --cov=viabilityscan --cov-report=term-missing --cov-fail-under=70

lint:
	ruff check viabilityscan/

dashboard:
	python dashboard/app.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f viability_report.json

gaps:
	@echo "=== Agent Gaps ==="
	@cat agents.jsonl | python3 -c "import sys,json; [print(json.loads(l)['id'], '|', json.loads(l)['priority'], '|', json.loads(l)['title']) for l in sys.stdin]"
