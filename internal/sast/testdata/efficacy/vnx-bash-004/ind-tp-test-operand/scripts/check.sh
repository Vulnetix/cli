#!/bin/bash
name=$1
~>if [ -z $name ]; then
  echo "name required" >&2
  exit 1
fi
~>if [ -f $2 ]; then
  source "$2"
fi
