#!/bin/sh
exec capsh --drop=cap_sys_admin,cap_sys_ptrace --caps="cap_net_bind_service+eip" -- -c /opt/web/bin/web
