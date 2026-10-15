#!/bin/sh
# curl prompts for the password when only the user is given.
curl -u deployer https://nexus.acme-corp.io/
curl --negotiate -u : https://intranet.acme-corp.io/
curl -u deployer: https://nexus.acme-corp.io/
