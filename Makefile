SHELL := /bin/bash
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

SEMGREP_ARGS=--use-git-ignore --metrics=off --force-color --disable-version-check --experimental --dataflow-traces --sarif --timeout=0
SEMGREP_RULES=-c p/default -c p/python -c p/php -c p/c -c p/rust -c p/apex -c p/nginx -c p/terraform -c p/csharp -c p/nextjs -c p/golang -c p/nodejs -c p/kotlin -c p/django -c p/docker -c p/kubernetes -c p/lockfiles -c p/supply-chain -c p/headless-browser -c p/expressjs -c p/cpp-audit -c p/mobsfscan -c p/ruby -c p/java -c p/javascript -c p/typescript -c p/bandit -c p/flask -c p/gosec -c p/flawfinder -c p/gitleaks -c p/eslint -c p/phpcs-security-audit -c p/react -c p/brakeman -c p/findsecbugs -c p/secrets -c p/sql-injection -c p/jwt -c p/insecure-transport -c p/command-injection -c p/security-code-scan -c p/xss

clean: ## Cleanup tmp files
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null

setup: ## FOR DOCO ONLY - Run these one at a time, do not call this target directly
	nvm install --lts
	nvm use --lts

migrate: ## migrate incoming schema changes for prisma orm
	npx wrangler d1 migrations apply vulnetix --local
	npx prisma generate

plan: ## plan a migrate for schema changes in prisma orm
	npx prisma migrate diff \
		--to-schema-datamodel ./prisma/schema.prisma \
		--script --from-local-d1 >migrations/0000_plan_TMP.sql

update: ## get app updates, migrate should be run first
	npm update --include dev
	npm run audit
	npm audit fix --force

install: ## install deps and build icons
	npm i
	npm run postinstall

sarif: clean ## generate SARIF from Semgrep for this project
	osv-scanner --format sarif --call-analysis=all -r . | jq >osv.sarif.json
	semgrep $(SEMGREP_ARGS) $(SEMGREP_RULES) | jq >semgrep.sarif.json

sbom: clean ## generate CycloneDX from NPM for this project
	npm sbom --omit dev --package-lock-only --sbom-format cyclonedx | jq >npm.cdx.json
	npm sbom --omit dev --package-lock-only --sbom-format spdx | jq >npm.spdx.json

deployments: ## FOR DOCO ONLY
	npx wrangler pages deployment list --project-name vulnetix

run: ## FOR DOCO ONLY - Run these one at a time, do not call this target directly
	lsof -i tcp:8788
	npm run preview

git-demo:
	[[ -z "$(shell git status -s)" ]] || git stash save "changes for demo"
	git checkout main
	git branch -D demo
	git fetch -a
	git pull
	git checkout -b demo main
	git push --set-upstream origin demo
	git stash pop || true

_purge_data: ## FOR DOCO ONLY
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM Finding;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM Triage;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM GitRepo;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM SARIFInfo;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM SarifResults;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM CycloneDXInfo;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM SPDXInfo;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM IntegrationUsageLog;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM Link;"
	npx wrangler d1 execute vulnetix --local --command "DELETE FROM Artifact;"

_helpers: ## FOR DOCO ONLY
	npx wrangler d1 execute vulnetix --local --file ./migrations/0001_init.sql
	npx wrangler d1 execute vulnetix --local --command "SELECT * FROM Member;"
	npx prisma migrate diff \
	--from-empty \
	--to-schema-datamodel ./prisma/schema.prisma \
	--script \
	--output migrations/0001_init.sql
