#!/bin/bash
cleanup() {
  rm -f $(find . -name '*.tmp')
}
