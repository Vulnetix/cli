#!/bin/sh
~>export IFS=";"
while getopts "d:" o; do
  case $o in
~>    d) IFS=$OPTARG ;;
  esac
done
