#!/bin/bash
name=$1
case $1 in
  start) echo go ;;
esac
if [[ $1 == stop ]]; then echo stop; fi
rm -- "$name"
count=$(( $2 + 1 ))
(( $2 > 3 )) && echo many
echo "$#" "$?"
