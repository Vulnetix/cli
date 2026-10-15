#!/bin/bash
~>for line in $(cat hosts.txt); do
  ping -c1 "$line"
done
~>for f in $(ls *.log); do
  gzip "$f"
done
