#include <string.h>

#define LEN 16

void set_name(char *dst_out, const char *src)
{
    char name[LEN + 1];
    strncpy(name, src, LEN);
    name[LEN] = '\0';

    int counts[LEN + 1];
    for (int i = 0; i <= LEN; i++)
        counts[i] = 0;

    char tail[LEN];
    tail[LEN - 1] = '\0';
    char *end = &tail[LEN];
    (void)end;
}
