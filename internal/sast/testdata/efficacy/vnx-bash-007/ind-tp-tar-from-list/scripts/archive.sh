#!/bin/bash
stamp=$(date +%F)
~>tar -czf "/backups/site-$stamp.tgz" $(cat include-list.txt)
~>rm -f $(grep -l 'DEPRECATED' config/*.yaml)
