#!/bin/bash
DIR=/opt/app
for f in a b c; do
  touch $DIR/$f
done
mkdir -p $DIR
