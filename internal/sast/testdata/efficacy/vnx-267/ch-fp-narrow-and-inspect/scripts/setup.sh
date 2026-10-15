#!/bin/sh
setcap cap_net_bind_service=+ep /usr/bin/node
setcap -r /usr/local/bin/agent
getcap /usr/local/bin/agent | grep -q cap_sys_admin && echo "agent still has cap_sys_admin"
echo "run: setcap cap_sys_admin+ep ./agent to enable mounting"
