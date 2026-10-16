#include <stdio.h>

int read_name(char *out, size_t outlen)
{
    char line[256];
    if (fgets(line, sizeof line, stdin) == NULL)
        return -1;
    snprintf(out, outlen, "%s", line);
    return 0;
}
