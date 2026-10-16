#!/bin/bash
~>export IFS=$'\n'
./bin/process-batch
make deploy
