SHELL := /bin/bash
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

clean: ## Cleanup tmp files
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null

setup: ## FOR DOCO ONLY - Run these one at a time, do not call this target directly
	uv venv --python $(which python3.12)
	source .venv/bin/activate	
	uv pip install -U pip

install: ## poetry install
	poetry install

test: clean ## pytest with coverage
	coverage run -m pytest --nf
	coverage report -m --fail-under=100
	coverage-badge -f -o coverage.svg

publish: clean sbom ## upload to pypi.org
	poetry publish --build
	git commit -a -s -m 'feat: v$(shell poetry version -s)'
	git tag --force v$(shell poetry version -s)
	git push
	git push --tags --force

sbom: ## generate CycloneDX for this project
	uv pip compile --generate-hashes -o requirements.txt --all-extras --upgrade pyproject.toml
	pip-audit -r requirements.txt -f cyclonedx-json --require-hashes | jq > sbom.json
