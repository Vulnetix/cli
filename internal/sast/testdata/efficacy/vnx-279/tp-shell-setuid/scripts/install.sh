#!/bin/sh
set -e
BIN=/usr/local/bin/backup

~>chmod u+s /usr/local/bin/backup
~>chmod 4755 "$BIN"
~>chmod +s /opt/tool/run
~>install -m 4755 helper /usr/libexec/helper
~>sudo chmod a+s /opt/tool/agent
