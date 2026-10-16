#include <stdio.h>
#include <string.h>
void f(FILE *in, const char *src)
{
    char line[80];
    char buf[64];
    fgets(line, sizeof(line), in);
    memcpy(buf, src, sizeof(buf));
    snprintf(buf, sizeof buf, "%s", line);
}
