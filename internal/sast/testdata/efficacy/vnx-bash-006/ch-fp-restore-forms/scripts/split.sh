#!/bin/bash
OLDIFS=$IFS
IFS=:
for d in $PATH; do echo "$d"; done
IFS=$OLDIFS
f() {
  IFS=,
  echo $1
  unset IFS
}
g() {
  IFS=';'
  echo $1
  IFS=$' \t\n'
}
