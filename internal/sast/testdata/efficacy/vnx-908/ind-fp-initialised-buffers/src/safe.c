#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(const char *who)
{
    char buf[64];
    snprintf(buf, sizeof buf, "hello %s", who);
    puts(buf);

    char *q = calloc(1, 64);
    if (!q)
        return;
    strcat(q, who);
    free(q);

    int count = 0;
    count += 2;
    char line[80] = "";
    strcat(line, who);
}
