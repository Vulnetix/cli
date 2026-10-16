#include <stdio.h>

/* Do not do send(sock, &len, sizeof(len), 0); use htonl first. */
// fwrite(hdr, sizeof(struct db_header), 1, fp) is non-portable
const char *warning = "never call write(fd, &n, sizeof(n)) on raw ints";

void hello(void) { puts(warning); }
