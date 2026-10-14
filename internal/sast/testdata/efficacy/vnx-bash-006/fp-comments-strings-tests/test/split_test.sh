#!/bin/bash
IFS=,
set -- a,b,c
[ "$#" -eq 3 ]
