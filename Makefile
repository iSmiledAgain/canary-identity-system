.PHONY: install test cov demo package clean

install:
	python3 -m pip install -r requirements-dev.txt

test:
	python3 -m pytest

cov:
	python3 -m pytest --cov=src --cov-report=term-missing

demo:
	python3 -m src.cli demo

# Build the Lambda deployment package Person A references from terraform/lambda.tf
package:
	rm -f lambda_payload.zip
	cd . && zip -r lambda_payload.zip src -x '*__pycache__*' '*.pyc' >/dev/null
	@echo "Built lambda_payload.zip (handler: src.handler.lambda_handler)"

clean:
	rm -rf .pytest_cache .coverage lambda_payload.zip
	find . -name __pycache__ -type d -exec rm -rf {} +
