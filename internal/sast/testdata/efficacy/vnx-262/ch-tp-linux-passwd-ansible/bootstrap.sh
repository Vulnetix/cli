#!/bin/sh
useradd -m appsvc
~>chage --maxdays -1 appsvc
~>echo 'PASS_MAX_DAYS 99999' | tee -a /etc/login.defs
