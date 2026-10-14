@test "installer leaves a writable spool" {
  chmod 777 "$BATS_TMPDIR/spool"
}
