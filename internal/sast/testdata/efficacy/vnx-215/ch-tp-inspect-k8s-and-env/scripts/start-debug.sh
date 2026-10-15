#!/bin/sh
set -e
~>exec node --inspect-brk=0.0.0.0:9229 server.js
