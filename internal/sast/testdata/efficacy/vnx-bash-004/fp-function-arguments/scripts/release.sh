#!/bin/bash
copy_artifact() {
  local src=$1
  cp $src /opt/release/
  [ -f $2 ] && rm $2
}

function package {
  tar -czf out.tgz $@
}

copy_artifact build/app build/old
package build
