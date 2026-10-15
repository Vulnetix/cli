#!/bin/bash
~>rm -f $(find . -name '*.tmp')
~>cp $(cat filelist.txt) /dest/
~>grep -l TODO $(git ls-files)
