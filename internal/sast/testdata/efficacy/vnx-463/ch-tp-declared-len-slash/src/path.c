#include <stdio.h>
#include <string.h>

void open_child(char *dir, const char *name)
{
    int n = (int) strlen(dir);
~>    dir[n] = '/';
    printf("opening %s%s\n", dir, name);
}
