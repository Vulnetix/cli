#include <stdio.h>

#undef gets
#define gets(s) DO_NOT_USE_gets(s)
char *gets(char *s);

int pump(struct conn *conn, char *buf)
{
    conn->gets(buf, 512);
    /* gets(buf) would overflow here */
    puts("gets() is banned");
    return 0;
}
