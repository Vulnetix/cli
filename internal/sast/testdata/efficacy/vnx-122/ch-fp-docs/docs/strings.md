# Copying strings

Never write `char *p = malloc(strlen(s)); strcpy(p, s);` because the
terminator does not fit. Use `strdup(s)` instead.
