#include <stdio.h>

/* Never write: char *out = malloc(strlen(name)); strcpy(out, name); */
// char *buf = malloc(64); strcpy(buf, argv[1]);
static const char *hint = "malloc(strlen(s)) forgets the terminator";

void show(void) { puts(hint); }
