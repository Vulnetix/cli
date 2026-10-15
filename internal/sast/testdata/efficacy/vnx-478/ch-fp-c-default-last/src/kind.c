#include <stdio.h>

void print_kind(int k)
{
    const char *name;
    switch (k) {
    case 0:
        name = "file";
        break;
    case 1:
        name = "directory";
        break;
    default:
        name = "unknown";
        break;
    }
    printf("%s\n", name);
}
