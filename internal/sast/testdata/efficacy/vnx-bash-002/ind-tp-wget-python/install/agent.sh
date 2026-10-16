#!/bin/sh
set -e
AGENT_VERSION="${AGENT_VERSION:-3.2.1}"
~>wget -qO- "https://downloads.example-monitoring.io/agent/${AGENT_VERSION}/install.py" | python3 - --api-region eu
systemctl enable --now monitoring-agent
