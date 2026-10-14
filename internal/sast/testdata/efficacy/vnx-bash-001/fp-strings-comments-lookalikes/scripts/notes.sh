#!/bin/sh
# eval "$cmd" would run anything the caller passes, so it is not used here.
echo "never eval $input; use a case statement"
printf 'do not run: eval %s\n' "$1"
. gettext.sh
eval_gettext "Installing \$package"
retval=$?
evaluate_results "$1"
node --eval "console.log(process.version)"
perl -e 'eval { die "x" }; print $@'
echo "retry with: eval \"\$(tool env)\""
