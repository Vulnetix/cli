#include <string.h>

void put_infinity(char *dst)
{
    char buf[16];
    memcpy(buf, "inf", 3);
    buf[3] = '\0';
    strcpy(dst, buf);
}
