#!/bin/bash

run_hooks() {
  local hook="$1"
~>  [ -n "$hook" ] && eval "$hook"
~>  if eval "$CHECK_CMD"; then
    echo "check passed"
  fi
~>  result=$(eval "$EXPRESSION")
  echo "$result"
~>  cd /srv/app; eval "$DEPLOY_STEP"
~>  user_home=$(eval echo "~$REQUESTED_USER")
  echo "$user_home"
  case "$2" in
~>    custom) eval "$3" ;;
    *) echo "default" ;;
  esac
~>  ! eval "$NEGATED"
~>  command eval "$RAW_INPUT"
}
