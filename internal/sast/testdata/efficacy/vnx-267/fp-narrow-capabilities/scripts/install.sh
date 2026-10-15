#!/bin/sh
setcap cap_net_bind_service=+ep /usr/local/bin/web
getcap /usr/local/bin/agent | grep -q cap_sys_admin && echo "too broad"
setcap -r /usr/local/bin/agent
