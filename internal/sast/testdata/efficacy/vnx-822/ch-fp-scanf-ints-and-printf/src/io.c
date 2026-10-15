#include <stdio.h>

void io(const char *line, void *p)
{
    int a, b;
    sscanf(line, "%d %d", &a, &b);
    printf("pointer %p\n", p);
    fprintf(stderr, "a=%d b=%d at %p\n", a, b, p);
    /* sscanf(line, "%p", &p); was removed */
}
