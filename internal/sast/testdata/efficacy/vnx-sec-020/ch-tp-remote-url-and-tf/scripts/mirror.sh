#!/bin/sh
~>git clone https://oauth2:glpat-@@sample:[A-Za-z0-9]{20}@@@gitlab.com/acme/platform.git
~>docker login registry.gitlab.com -u deployer -p gldt-@@sample:[A-Za-z0-9]{20}@@
