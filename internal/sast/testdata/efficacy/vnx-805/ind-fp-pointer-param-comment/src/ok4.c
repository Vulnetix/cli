#include <string.h>
static void first(void)
{
    char buf[8];
    buf[0] = 0;
}
static void second(char *buf, const char *src)
{
    memcpy(buf, src, 128);
}
void third(void)
{
    /* memcpy(tmp, src, 999); */
    const char *s = "read(fd, name, 4096)";
    (void)s;
}
