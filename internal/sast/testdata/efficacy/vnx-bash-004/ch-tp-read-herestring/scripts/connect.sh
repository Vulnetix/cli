#!/bin/bash
IFS=, read -r user host <<< "$1"
~>ssh $user@$host uptime
