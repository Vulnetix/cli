#!/bin/bash
sysctl -w net.core.somaxconn=1024
sysctl -w vm.swappiness=10
gcc -Wall -Wextra -Werror -o out main.c
