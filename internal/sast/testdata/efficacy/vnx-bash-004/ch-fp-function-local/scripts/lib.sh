#!/bin/bash
greet() {
  local who=$1
  printf 'Hello %s\n' "$who"
}
greet "world"
