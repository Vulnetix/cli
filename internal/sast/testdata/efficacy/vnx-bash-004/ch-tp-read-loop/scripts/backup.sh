#!/bin/bash
while read -r path; do
~>  cp $path /backup/
done < list.txt
