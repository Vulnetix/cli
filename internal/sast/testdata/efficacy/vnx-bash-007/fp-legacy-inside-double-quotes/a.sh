echo "size: $(wc -c < "$f" 2>/dev/null || echo unknown) bytes" >&2
echo "- **Host:** $(uname -sm), $(nproc 2>/dev/null || echo '?') cores"
x=$(date +%s)
for run in $(seq 1 "$RUNS"); do :; done
