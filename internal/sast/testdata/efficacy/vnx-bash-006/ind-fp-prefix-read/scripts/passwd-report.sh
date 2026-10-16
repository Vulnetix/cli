#!/bin/bash
while IFS=: read -r user _ uid gid _ home shell; do
  [ "$uid" -ge 1000 ] && echo "$user $home $shell"
done < /etc/passwd

IFS=, read -r first second <<< "alpha,beta"
echo "$first $second"
