# Porting notes

Replace every `strcpy(dst, src)` with `strlcpy(dst, src, sizeof dst)` and
never call `gets(buf)`; use `fgets(buf, sizeof buf, stdin)` instead.
