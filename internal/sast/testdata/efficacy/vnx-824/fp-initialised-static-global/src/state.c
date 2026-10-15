#include <stdio.h>

char *global_name;

void show(void)
{
    static char *cache;
    char *p = NULL;
    char *q = "fixed";
    if (cache) puts(cache);
    if (p) puts(p);
    puts(q);
    puts(global_name);
}
