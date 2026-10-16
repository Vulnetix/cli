#include <stdio.h>
void load(const char *line)
{
    void *ptr = NULL;
~>    if (sscanf(line, "%p", &ptr) == 1) {
~>        *(int *)ptr = 0;
    }
}
