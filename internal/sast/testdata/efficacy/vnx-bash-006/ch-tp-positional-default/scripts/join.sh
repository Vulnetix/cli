#!/bin/bash
~>IFS="${1:-,}"
set -- $2
echo "$#"
