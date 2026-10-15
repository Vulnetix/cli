#!/bin/sh
set -e
install -m 0755 build/agent /usr/local/bin/agent
~>setcap cap_sys_admin,cap_net_admin+ep /usr/local/bin/agent
~>setcap 'cap_dac_read_search=eip' /usr/local/bin/indexer
