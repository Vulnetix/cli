#!/bin/bash
split_path() {
~>  IFS=:
  set -- $PATH
  echo "$#"
}
split_path
