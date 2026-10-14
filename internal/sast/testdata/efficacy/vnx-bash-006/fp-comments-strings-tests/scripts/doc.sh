#!/bin/bash
# IFS=, would change splitting for the whole script
echo 'use IFS=, inside a function with local'
MY_IFS=","
CUSTOM_IFS=$'\t'
