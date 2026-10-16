#include <stdio.h>
#include <string.h>

int prompt(char *buf, int size)
{
    if (!fgets(buf, size, stdin))
        return -1;
    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}
