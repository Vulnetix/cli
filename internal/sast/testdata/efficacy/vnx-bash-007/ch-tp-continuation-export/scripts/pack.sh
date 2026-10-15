#!/bin/bash
~>export $(grep -v '^#' .env | xargs)
~>chmod +x $(find bin -type f)
tar -czf src.tgz \
~>  $(git ls-files)
