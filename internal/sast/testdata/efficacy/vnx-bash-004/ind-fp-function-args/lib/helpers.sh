#!/bin/bash
copy_to_opt() {
  cp $1 /opt/
}

log_msg() {
  logger -t deploy $1 $2
}

copy_to_opt "./dist/app.jar"
log_msg info started
