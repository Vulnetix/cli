---
title: "Secrets — Source Control & CI/CD"
description: "GitHub, GitLab, Bitbucket, Azure DevOps tokens and CI/CD pipeline credentials."
weight: 2
---

GitHub, GitLab, Bitbucket, Azure DevOps tokens and CI/CD pipeline credentials.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-181"></a>VNX-SEC-181 | Bitbucket app password | High | keyword + regex + entropy |
| <a id="vnx-sec-182"></a>VNX-SEC-182 | Bitbucket app password (ATBB prefix) | High | keyword + regex |
| <a id="vnx-sec-183"></a>VNX-SEC-183 | Bitbucket OAuth client secret | High | keyword + regex + entropy |
| <a id="vnx-sec-184"></a>VNX-SEC-184 | Azure DevOps personal access token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-185"></a>VNX-SEC-185 | CircleCI personal API token | High | keyword + regex + entropy |
| <a id="vnx-sec-186"></a>VNX-SEC-186 | CircleCI project API token (CCIP) | High | keyword + regex |
| <a id="vnx-sec-187"></a>VNX-SEC-187 | Travis CI API token | High | keyword + regex + entropy |
| <a id="vnx-sec-188"></a>VNX-SEC-188 | Buildkite agent token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-189"></a>VNX-SEC-189 | Buildkite API access token | High | keyword + regex + entropy |
| <a id="vnx-sec-190"></a>VNX-SEC-190 | Jenkins API token | High | keyword + regex + entropy |
| <a id="vnx-sec-191"></a>VNX-SEC-191 | Jenkins crumb (CSRF token) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-192"></a>VNX-SEC-192 | Drone CI token | High | keyword + regex + entropy |
| <a id="vnx-sec-193"></a>VNX-SEC-193 | TeamCity access token | High | keyword + regex |
| <a id="vnx-sec-194"></a>VNX-SEC-194 | TeamCity access token (generic) | High | keyword + regex + entropy |
| <a id="vnx-sec-195"></a>VNX-SEC-195 | Gitea access token | High | keyword + regex + entropy |
| <a id="vnx-sec-196"></a>VNX-SEC-196 | Gitee access token | High | keyword + regex + entropy |
| <a id="vnx-sec-197"></a>VNX-SEC-197 | Codecov upload token | Medium | keyword + regex |
| <a id="vnx-sec-198"></a>VNX-SEC-198 | Coveralls repo token | Medium | keyword + regex + entropy |
| <a id="vnx-sec-199"></a>VNX-SEC-199 | Code Climate test reporter ID | Medium | keyword + regex + entropy |
| <a id="vnx-sec-200"></a>VNX-SEC-200 | Sourcegraph access token (sgp_) | High | keyword + regex |
| <a id="vnx-sec-201"></a>VNX-SEC-201 | Sourcegraph dotcom token (sgph_) | High | keyword + regex |
| <a id="vnx-sec-202"></a>VNX-SEC-202 | Semaphore CI token | High | keyword + regex + entropy |
| <a id="vnx-sec-203"></a>VNX-SEC-203 | Harness personal access token (pat.) | Critical | keyword + regex |
| <a id="vnx-sec-204"></a>VNX-SEC-204 | Harness service account token (sat.) | Critical | keyword + regex |
| <a id="vnx-sec-205"></a>VNX-SEC-205 | Spacelift API token | High | keyword + regex |
| <a id="vnx-sec-206"></a>VNX-SEC-206 | Pulumi access token (pul-) | Critical | keyword + regex |
| <a id="vnx-sec-207"></a>VNX-SEC-207 | Octopus Deploy API key (API-) | High | keyword + regex + entropy |
| <a id="vnx-sec-208"></a>VNX-SEC-208 | Terraform Cloud team/org token | Critical | keyword + regex |
| <a id="vnx-sec-209"></a>VNX-SEC-209 | JFrog access/identity token | High | keyword + regex + entropy |
| <a id="vnx-sec-210"></a>VNX-SEC-210 | JFrog reference token (cmVmdGtuOjA) | High | keyword + regex |
| <a id="vnx-sec-211"></a>VNX-SEC-211 | Argo CD auth token (JWT) | Critical | keyword + regex |
| <a id="vnx-sec-212"></a>VNX-SEC-212 | FluxCD git credentials | High | keyword + regex + entropy |
| <a id="vnx-sec-213"></a>VNX-SEC-213 | GitHub App private key (PEM) | Critical | keyword + regex |
| <a id="vnx-sec-214"></a>VNX-SEC-214 | GitHub Actions runner registration token (BBBB) | High | keyword + regex + entropy |
| <a id="vnx-sec-215"></a>VNX-SEC-215 | Vercel deploy hook URL | High | keyword + regex |
| <a id="vnx-sec-216"></a>VNX-SEC-216 | Vercel API token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-217"></a>VNX-SEC-217 | Bitrise access token | High | keyword + regex + entropy |
| <a id="vnx-sec-218"></a>VNX-SEC-218 | Codefresh API token | High | keyword + regex + entropy |
| <a id="vnx-sec-219"></a>VNX-SEC-219 | Woodpecker CI token | High | keyword + regex + entropy |
| <a id="vnx-sec-220"></a>VNX-SEC-220 | Concourse CI token | High | keyword + regex + entropy |
| <a id="vnx-sec-221"></a>VNX-SEC-221 | GoCD access token | High | keyword + regex + entropy |
| <a id="vnx-sec-222"></a>VNX-SEC-222 | Sentry CLI auth token (sntrys_) | High | keyword + regex |
| <a id="vnx-sec-223"></a>VNX-SEC-223 | Sentry user auth token (sntryu_) | High | keyword + regex |
| <a id="vnx-sec-224"></a>VNX-SEC-224 | ReadTheDocs API token | Medium | keyword + regex + entropy |
| <a id="vnx-sec-225"></a>VNX-SEC-225 | Netlify build hook URL | High | keyword + regex |
| <a id="vnx-sec-226"></a>VNX-SEC-226 | Netlify API access token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-227"></a>VNX-SEC-227 | Cloudsmith API key | High | keyword + regex + entropy |
| <a id="vnx-sec-228"></a>VNX-SEC-228 | Bitbucket Pipelines OIDC/step token | High | keyword + regex + entropy |
| <a id="vnx-sec-229"></a>VNX-SEC-229 | TeamCity superuser token | Critical | keyword + regex |
| <a id="vnx-sec-230"></a>VNX-SEC-230 | Drone CI RPC secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-231"></a>VNX-SEC-231 | Sourcegraph dotcom token (sgd_) | High | keyword + regex |
| <a id="vnx-sec-232"></a>VNX-SEC-232 | Buildkite registration token (bkua_) | Critical | keyword + regex |
| <a id="vnx-sec-233"></a>VNX-SEC-233 | Codecov global upload token (legacy) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-234"></a>VNX-SEC-234 | Argo CD admin password | Critical | keyword + regex + entropy |
| <a id="vnx-sec-235"></a>VNX-SEC-235 | Semaphore organization API token (legacy) | High | keyword + regex |
| <a id="vnx-sec-236"></a>VNX-SEC-236 | Spacelift API key secret | High | keyword + regex + entropy |
| <a id="vnx-sec-237"></a>VNX-SEC-237 | Codefresh runtime/agent token | High | keyword + regex + entropy |
| <a id="vnx-sec-238"></a>VNX-SEC-238 | TeamCity build agent authorization token | High | keyword + regex + entropy |
| <a id="vnx-sec-239"></a>VNX-SEC-239 | JFrog Pipelines integration token | High | keyword + regex + entropy |
| <a id="vnx-sec-240"></a>VNX-SEC-240 | GitHub Actions runner token (config.sh) | High | keyword + regex |
| <a id="vnx-sec-241"></a>VNX-SEC-241 | Gitea OAuth client secret | High | keyword + regex |
| <a id="vnx-sec-242"></a>VNX-SEC-242 | Travis CI Pro/Enterprise access token (legacy) | High | keyword + regex + entropy |
| <a id="vnx-sec-243"></a>VNX-SEC-243 | FluxCD GitRepository SSH private key | Critical | keyword + regex |
| <a id="vnx-sec-244"></a>VNX-SEC-244 | Concourse fly target token | High | keyword + regex |
| <a id="vnx-sec-245"></a>VNX-SEC-245 | Cloudsmith entitlement token (cmVudA / ent_) | High | keyword + regex + entropy |
| <a id="vnx-sec-246"></a>VNX-SEC-246 | Octopus Deploy server API key (assignment) | High | keyword + regex |
| <a id="vnx-sec-247"></a>VNX-SEC-247 | Pulumi config passphrase | High | keyword + regex + entropy |
| <a id="vnx-sec-248"></a>VNX-SEC-248 | Drone CI machine/user token (legacy) | High | keyword + regex + entropy |
| <a id="vnx-sec-249"></a>VNX-SEC-249 | Gitee OAuth client secret | High | keyword + regex + entropy |
| <a id="vnx-sec-250"></a>VNX-SEC-250 | CircleCI context/environment token (assignment) | High | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
