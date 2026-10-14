#!/bin/bash
out=$1
MSG="line one
line two with $out
end"
awk '{
  print $1, $2
}' input.txt
~>cat input.txt > $out
