#!/bin/bash
~>export IFS=';'
~>IFS="$1"
read -r a b <<< "$2"
~>IFS=$OPTARG
