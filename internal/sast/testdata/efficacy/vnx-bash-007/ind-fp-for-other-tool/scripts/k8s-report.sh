#!/bin/bash
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl get pods -n "$ns"
done
# chmod 600 $(find . -name '*.key')
echo "Run chmod 600 $(printf '%s' keys) manually"
printf 'files: %s\n' $(ls)
