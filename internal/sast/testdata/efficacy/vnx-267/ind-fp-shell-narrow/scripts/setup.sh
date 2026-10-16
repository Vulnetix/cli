#!/bin/sh
setcap cap_net_bind_service=+ep /usr/bin/node
setcap -r /usr/local/bin/agent
capsh --drop=cap_sys_admin,cap_sys_ptrace -- -c "/usr/local/bin/worker"
echo "do not run: setcap cap_sys_admin+ep on the agent"
# setcap cap_sys_admin+ep /usr/local/bin/agent   (old approach)
docker run --cap-add SYS_ADMIN --rm debug-image
