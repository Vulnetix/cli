#include <stdio.h>

/* Never do send(sock, &len, sizeof(len), 0) without htonl. */
// fwrite(&hdr, sizeof(hdr), 1, fp) writes padding bytes too.
static const char *hint = "write(fd, &n, sizeof(n))";

void show(void)
{
    puts(hint);
}
