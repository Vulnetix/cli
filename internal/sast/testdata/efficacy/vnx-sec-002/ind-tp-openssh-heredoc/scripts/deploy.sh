#!/bin/bash
cat > ~/.ssh/id_deploy <<KEY
~>-----BEGIN OPENSSH PRIVATE KEY-----
@@sample:[A-Za-z0-9+/]{70}@@
@@sample:[A-Za-z0-9+/]{70}@@
-----END OPENSSH PRIVATE KEY-----
KEY
chmod 600 ~/.ssh/id_deploy
