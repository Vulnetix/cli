#!/bin/bash
msg="$1"
~>curl -s "https://api.telegram.org/bot@@sample:[0-9]{9}:AA[A-Za-z0-9_-]{33}@@/sendMessage" -d chat_id=-100123456 -d text="$msg"
