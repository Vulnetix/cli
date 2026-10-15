#include <string.h>

int
clear_name(buf, len)
    char *buf;
    int len;
{
    memset(buf, 0, len);
    buf[0] = '\0';
    return 0;
}
