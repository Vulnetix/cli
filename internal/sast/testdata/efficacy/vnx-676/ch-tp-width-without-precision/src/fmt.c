#include <stdio.h>
#include <string.h>

void row(char *out, const char *name, const char *prog)
{
~>    sprintf(out, "%-20s|", name);
~>    int n = sprintf(out, "%s: %s\n", prog, strerror(errno));
}
