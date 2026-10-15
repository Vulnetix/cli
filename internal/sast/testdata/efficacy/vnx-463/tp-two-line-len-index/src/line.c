#include <string.h>
#include <stdio.h>

void mark_line(char *buf)
{
    size_t len = strlen(buf);
~>    buf[len] = '\n';
    fputs(buf, stdout);
}
