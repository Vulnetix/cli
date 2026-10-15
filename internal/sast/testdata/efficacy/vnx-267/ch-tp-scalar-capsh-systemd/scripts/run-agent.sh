#!/bin/sh
~>exec capsh --caps="cap_sys_ptrace,cap_setpcap+eip" --addamb=cap_sys_ptrace -- -c /opt/agent/bin/agent
