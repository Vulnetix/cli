#!/usr/bin/env bash
set -euo pipefail
KUBECTL_VERSION=v1.30.2
curl -fsSLo kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
curl -fsSLo kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl.sha256"
install -m 0755 kubectl /usr/local/bin/kubectl
