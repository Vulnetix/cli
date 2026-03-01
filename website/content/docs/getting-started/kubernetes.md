---
title: "Kubernetes"
weight: 7
description: "Run Vulnetix CLI in Kubernetes environments using Jobs and CronJobs."
---

Run Vulnetix CLI in Kubernetes environments using our official Docker images.

## Quick Start

```yaml
# Simple Job to run vulnerability scan
apiVersion: batch/v1
kind: Job
metadata:
  name: vulnetix-scan
spec:
  template:
    spec:
      containers:
      - name: vulnetix
        image: vulnetix/vulnetix:latest
        args:
          - "--org-id"
          - "your-org-id-here"
          - "--task"
          - "scan"
          - "--project-name"
          - "my-k8s-app"
        env:
        - name: VULNETIX_ORG_ID
          valueFrom:
            secretKeyRef:
              name: vulnetix-secrets
              key: org-id
      restartPolicy: Never
```

## Installation

Vulnetix uses the same Docker images as documented in [Docker Reference](docker.md). No separate Kubernetes-specific images are needed.

### Available Images

```bash
# Pull images (same as Docker)
docker pull vulnetix/vulnetix:latest
docker pull vulnetix/vulnetix:v1.2.3

# Multi-architecture support
# Kubernetes automatically selects the correct architecture
```

## Configuration

### Create Secret for Org ID

```bash
# Create secret from command line
kubectl create secret generic vulnetix-secrets \
  --from-literal=org-id="123e4567-e89b-12d3-a456-426614174000"

# Or from YAML
apiVersion: v1
kind: Secret
metadata:
  name: vulnetix-secrets
type: Opaque
data:
  org-id: MTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAw  # base64 encoded
```

### ConfigMap for Advanced Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnetix-config
data:
  project-name: "my-kubernetes-app"
  team-name: "platform-team"
  tags: '["Public", "Crown Jewels"]'
  tools: |
    [
      {
        "category": "CONTAINER",
        "tool_name": "trivy",
        "artifact_name": "k8s-scan",
        "format": "SARIF"
      }
    ]
```

## Usage Examples

### Basic Vulnerability Scanning

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: vulnetix-vulnerability-scan
spec:
  template:
    spec:
      containers:
      - name: vulnetix
        image: vulnetix/vulnetix:latest
        args:
          - "--org-id"
          - "$(VULNETIX_ORG_ID)"
          - "--task"
          - "scan"
          - "--project-name"
          - "$(PROJECT_NAME)"
          - "--team-name"
          - "$(TEAM_NAME)"
        env:
        - name: VULNETIX_ORG_ID
          valueFrom:
            secretKeyRef:
              name: vulnetix-secrets
              key: org-id
        - name: PROJECT_NAME
          valueFrom:
            configMapKeyRef:
              name: vulnetix-config
              key: project-name
        - name: TEAM_NAME
          valueFrom:
            configMapKeyRef:
              name: vulnetix-config
              key: team-name
      restartPolicy: Never
  backoffLimit: 3
```

### Release Assessment

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: vulnetix-release-assessment
spec:
  template:
    spec:
      containers:
      - name: vulnetix
        image: vulnetix/vulnetix:latest
        args:
          - "--org-id"
          - "$(VULNETIX_ORG_ID)"
          - "--task"
          - "release"
          - "--project-name"
          - "$(PROJECT_NAME)"
          - "--team-name"
          - "$(TEAM_NAME)"
          - "--production-branch"
          - "main"
          - "--release-branch"
          - "release/v1.0.0"
          - "--workflow-timeout"
          - "60"
        env:
        - name: VULNETIX_ORG_ID
          valueFrom:
            secretKeyRef:
              name: vulnetix-secrets
              key: org-id
        - name: PROJECT_NAME
          valueFrom:
            configMapKeyRef:
              name: vulnetix-config
              key: project-name
        - name: TEAM_NAME
          valueFrom:
            configMapKeyRef:
              name: vulnetix-config
              key: team-name
      restartPolicy: Never
  backoffLimit: 2
```

### SARIF Upload Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: vulnetix-sarif-upload
spec:
  template:
    spec:
      containers:
      - name: vulnetix
        image: vulnetix/vulnetix:latest
        command:
          - "vulnetix"
          - "sarif"
          - "--org-id"
          - "$(VULNETIX_ORG_ID)"
          - "--project-name"
          - "$(PROJECT_NAME)"
          - "/data/scan-results.sarif"
        env:
        - name: VULNETIX_ORG_ID
          valueFrom:
            secretKeyRef:
              name: vulnetix-secrets
              key: org-id
        - name: PROJECT_NAME
          valueFrom:
            configMapKeyRef:
              name: vulnetix-config
              key: project-name
        volumeMounts:
        - name: sarif-data
          mountPath: /data
      volumes:
      - name: sarif-data
        persistentVolumeClaim:
          claimName: scan-results-pvc
      restartPolicy: Never
```

### CronJob for Scheduled Scans

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vulnetix-scheduled-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: vulnetix
            image: vulnetix/vulnetix:latest
            args:
              - "--org-id"
              - "$(VULNETIX_ORG_ID)"
              - "--task"
              - "scan"
              - "--project-name"
              - "$(PROJECT_NAME)"
              - "--tags"
              - "$(TAGS)"
            env:
            - name: VULNETIX_ORG_ID
              valueFrom:
                secretKeyRef:
                  name: vulnetix-secrets
                  key: org-id
            - name: PROJECT_NAME
              valueFrom:
                configMapKeyRef:
                  name: vulnetix-config
                  key: project-name
            - name: TAGS
              valueFrom:
                configMapKeyRef:
                  name: vulnetix-config
                  key: tags
          restartPolicy: OnFailure
```

## CI/CD Integration

### GitOps with ArgoCD

```yaml
# Application manifest
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: vulnetix-security-scans
spec:
  source:
    repoURL: https://github.com/your-org/k8s-security-jobs
    path: vulnetix/
    targetRevision: HEAD
  destination:
    server: https://kubernetes.default.svc
    namespace: security
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### Helm Chart Values

```yaml
# values.yaml for Vulnetix Helm chart
vulnetix:
  image:
    repository: vulnetix/vulnetix
    tag: "latest"
    pullPolicy: IfNotPresent

  config:
    orgId: "your-org-id"  # Will be moved to secret
    projectName: "my-k8s-project"
    teamName: "platform-team"

  schedule:
    enabled: true
    cron: "0 2 * * *"

  resources:
    limits:
      cpu: 500m
      memory: 512Mi
    requests:
      cpu: 100m
      memory: 128Mi
```

## Resource Management

### Resource Limits

```yaml
containers:
- name: vulnetix
  image: vulnetix/vulnetix:latest
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 100m
      memory: 256Mi
```

### Pod Security Context

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
  - name: vulnetix
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
```

## Multi-Architecture Support

Vulnetix Docker images support multiple architectures. Kubernetes automatically selects the correct image:

- **Linux AMD64** - `linux/amd64`
- **Linux ARM64** - `linux/arm64` (Apple Silicon, AWS Graviton)
- **Linux ARM** - `linux/arm/v7` (Raspberry Pi)

```yaml
# No architecture-specific configuration needed
containers:
- name: vulnetix
  image: vulnetix/vulnetix:latest  # Kubernetes picks the right arch
```

## Troubleshooting

### Pod Fails to Start

```bash
# Check pod status
kubectl describe pod vulnetix-scan-xxxxx

# Check logs
kubectl logs vulnetix-scan-xxxxx

# Common issues:
# - Missing secrets
# - Invalid org-id
# - Network connectivity
```

### Permission Issues

```yaml
# Add service account if needed
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnetix-sa
---
# Use in job
spec:
  template:
    spec:
      serviceAccountName: vulnetix-sa
```

### Network Policies

```yaml
# Allow egress for Vulnetix API calls
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vulnetix-egress
spec:
  podSelector:
    matchLabels:
      app: vulnetix
  policyTypes:
  - Egress
  egress:
  - to: []  # Allow all egress (adjust as needed)
    ports:
    - protocol: TCP
      port: 443
```

## Best Practices

1. **Use Secrets for Sensitive Data**
   - Store org-id in Kubernetes secrets
   - Never hardcode credentials in manifests

2. **Set Resource Limits**
   - Prevent resource exhaustion
   - Use appropriate CPU/memory limits

3. **Use Specific Image Tags**
   - Pin to specific versions for production
   - Use `latest` only for development

4. **Monitor Job Completion**
   - Set up alerts for failed jobs
   - Use appropriate backoff limits

5. **Namespace Isolation**
   - Run security scans in dedicated namespace
   - Apply appropriate RBAC policies

## Related Documentation

- [Docker Reference](docker.md) - Base Docker image documentation
- [GitHub Actions](github-actions.md) - CI/CD integration
- [CLI Reference](CLI-REFERENCE.md) - Complete CLI flag reference
