#include <stdio.h>

void report(FILE *log, const char *user, int code)
{
~>    printf("user %s failed with %d\n", user);
~>    fprintf(log, "%s\n", user, code);
}
