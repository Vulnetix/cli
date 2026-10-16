#!/bin/bash
cd "$PROJECT_DIR"
ls -la
git log --oneline -n 20
du -sh .
rm -f /tmp/report.lock
