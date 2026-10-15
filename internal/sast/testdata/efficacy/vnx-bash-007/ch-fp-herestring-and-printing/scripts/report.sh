#!/bin/bash
grep -c error <<< $(cat app.log)
if [[ -n $(ls -A "$dir") ]]; then echo nonempty; fi
echo Files: $(ls)
msg="Summary:
$(git log --oneline -5)
"
printf '%s\n' "$msg"
