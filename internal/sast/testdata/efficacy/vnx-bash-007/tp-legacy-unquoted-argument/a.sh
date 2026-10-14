~>rm -rf $(find . -name '*.tmp')
~>for f in $(ls /tmp); do echo "$f"; done
~>set -- $(cd "$FIX" && ls)
echo "$(ls /tmp)"
