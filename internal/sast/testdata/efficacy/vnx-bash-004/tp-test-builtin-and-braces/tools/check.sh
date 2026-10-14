#!/bin/sh
name=$1
~>if [ -n $name ]; then
  echo "checking $name"
fi
~>if [ $1 = "--help" ]; then
  exit 0
fi
~>test -f ${2}
~>[ -d ${name:-/tmp} ] && echo found
