#!/bin/bash
attempts=$1
if [ $# -lt 1 ]; then
  exit $?
fi
kill $$
wait $!
echo "pid $$ args $#"
sleep $(( attempts * 2 ))
count=$((count + $1))
echo ${#attempts}
shift
