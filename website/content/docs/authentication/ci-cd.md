---
title: "Authentication in CI/CD"
weight: 6
description: "Ephemeral credentials, secret masking, and per-platform wiring for GitHub Actions, GitLab, Bitbucket, Azure DevOps, Jenkins, and Kubernetes."
---

## The Rule

**Set environment variables. Do not run `vulnetix auth login`.**

Environment variables sit at the top of the [precedence chain](../precedence/), persist nothing, and disappear with the job. A login step buys you nothing on an ephemeral runner and leaves a plaintext `credentials.json` in a workspace that may be cached, uploaded as an artifact, or shared between steps.

```yaml
env:
  VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
  VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
```

Then verify before doing work:

```sh
vulnetix auth verify
```

`auth verify` reads the credential, calls the API, exits non-zero on failure, and writes nothing.

{{< callout type="warning" >}}
`--store keyring` on a CI runner silently falls back to a plaintext file, because there is no Secret Service on the D-Bus session bus. You get file storage with the appearance of keychain storage. Use environment variables instead.
{{< /callout >}}

## Choosing a Credential for CI

| Credential | Suitability |
|------------|-------------|
| **Bearer token** (`VULNETIX_API_TOKEN`) | Best. Org-less, revocable individually, no second variable to leak. |
| **ApiKey** (`VULNETIX_API_KEY` + `VULNETIX_ORG_ID`) | Fine. Two variables; the org ID is not sensitive. |
| **SigV4** (`VVD_ORG` + `VVD_SECRET`) | Avoid. The secret derives request keys; do not expose it to a shared runner. |

Issue a **distinct** token per pipeline. A token shared across repositories cannot be revoked without breaking all of them, and its use cannot be attributed.

---

## GitHub Actions

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
    steps:
      - uses: actions/checkout@v5

      - name: Install Vulnetix CLI
        run: curl -fsSL https://cli.vulnetix.com/install.sh | sh

      - name: Verify authentication
        run: vulnetix auth verify

      - name: Scan
        run: vulnetix scan --severity high
```

Values from `secrets.*` are masked in logs automatically. Values you compute are not — register them:

```sh
echo "::add-mask::$DERIVED_TOKEN"
```

The native action takes `org-id` and `api-key` inputs and runs `vulnetix auth login --api-key … --org-id … --store project` internally. That writes `./.vulnetix/credentials.json` into the workspace. It is safe on an ephemeral runner, but do not upload the workspace as an artifact afterwards. See [GitHub Actions](/docs/ci-cd/github-actions/).

## GitLab CI

Mark the variables **Masked** and **Protected** in *Settings → CI/CD → Variables*. A value is maskable when it is a single line, contains no spaces, and is at least 8 characters — both an ApiKey hex digest and a UUID qualify. **Protected** restricts the variable to pipelines on protected branches and tags.

```yaml
vulnetix:
  stage: security
  image: golang:latest
  variables:
    VULNETIX_ORG_ID: $VULNETIX_ORG_ID
    VULNETIX_API_KEY: $VULNETIX_API_KEY
  before_script:
    - curl -fsSL https://cli.vulnetix.com/install.sh | sh
    - vulnetix auth verify
  script:
    - vulnetix scan --severity high
```

## Bitbucket Pipelines

Define secured repository variables. Bitbucket redacts them from logs.

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Vulnetix
          image: golang:latest
          script:
            - curl -fsSL https://cli.vulnetix.com/install.sh | sh
            - vulnetix auth verify
            - vulnetix scan --severity high
```

## Azure DevOps

Store credentials in a variable group backed by Azure Key Vault. Mark them secret so they are not passed to the task environment implicitly — map them explicitly.

```yaml
steps:
  - task: Bash@3
    displayName: Vulnetix scan
    env:
      VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)
      VULNETIX_API_KEY: $(VULNETIX_API_KEY)
    inputs:
      targetType: inline
      script: |
        curl -fsSL https://cli.vulnetix.com/install.sh | sh
        vulnetix auth verify
        vulnetix scan --severity high
```

Secret variables in Azure Pipelines are **not** injected into the environment automatically. Omitting the `env:` block gives you an empty `VULNETIX_API_KEY` and a silent fall through to community access.

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Vulnetix') {
      steps {
        withCredentials([
          string(credentialsId: 'vulnetix-org-id',  variable: 'VULNETIX_ORG_ID'),
          string(credentialsId: 'vulnetix-api-key', variable: 'VULNETIX_API_KEY')
        ]) {
          sh '''
            curl -fsSL https://cli.vulnetix.com/install.sh | sh
            vulnetix auth verify
            vulnetix scan --severity high
          '''
        }
      }
    }
  }
}
```

Use `withCredentials` rather than an `environment { }` block: the binding is scoped to the step, and Jenkins masks the value in console output.

Never use `sh "… ${VULNETIX_API_KEY} …"` with double quotes — Groovy interpolates before the shell runs, and the secret is written to the build log as part of the command. Single quotes keep expansion in the shell.

## Kubernetes

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: vulnetix-scan
spec:
  template:
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: vulnetix
          image: ghcr.io/example/ci
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
          env:
            - name: VULNETIX_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: vulnetix
                  key: token
          command: ["vulnetix", "scan", "--severity", "high"]
```

`readOnlyRootFilesystem: true` guarantees no credential file can be written. Combined with `VULNETIX_API_TOKEN` this is the strongest configuration available.

---

## Rules That Apply Everywhere

**Never put the secret in argv.** Every process on the host can read `/proc/<pid>/cmdline`, and most CI systems echo the command before running it.

```sh
vulnetix auth login --api-key 6e40f1c3…   # leaks to logs and ps
export VULNETIX_API_KEY=…; vulnetix scan  # does not
```

**Never `echo` a credential to debug it.** Print its length or its source instead:

```sh
echo "key length: ${#VULNETIX_API_KEY}"
vulnetix auth status | head -n 6
```

**Do not persist the workspace after a `--store project` login.** If the native GitHub Action wrote `./.vulnetix/credentials.json`, that path must not appear in any `upload-artifact`, cache key, or subsequent `docker build` context.

```yaml
      - name: Remove workspace credentials
        if: always()
        run: rm -f .vulnetix/credentials.json
```

**Scope tokens per pipeline and rotate them.** See [Rotation & Revocation](../rotation/).

**Assert on the credential source** when a pipeline must not silently degrade to community access:

```sh
vulnetix auth status | grep -q 'environment' || {
  echo "expected an environment credential; refusing to continue"; exit 1;
}
```

Without this check, a typo in a secret name produces a scan that runs, reports fewer results at community rate limits, and exits `0`.
