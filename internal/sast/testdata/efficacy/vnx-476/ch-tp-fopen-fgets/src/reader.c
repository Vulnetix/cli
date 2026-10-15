#include <stdio.h>

int first_line(const char *path, char *out, int len)
{
    FILE *fp;
    fp = fopen(path, "r");
~>    if (fgets(out, len, fp) == NULL) {
        return -1;
    }
    return 0;
}
