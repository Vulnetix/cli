#!/bin/sh
~>chage --maxdays 400 alice
~>chage -M 1000 bob
~>echo "PASS_MAX_DAYS   400" >> /etc/login.defs
