#include <stdio.h>

/* gets(buf) can never be used safely */
// gets(buf);
static const char *msg = "never call gets(buf)";

void help(void) { puts(msg); }
