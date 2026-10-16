#include <stdio.h>

void render_status(char *out, size_t outlen, const char *tmpl)
{
~>    snprintf(out, outlen, tmpl);
}

void dump_reason(int fd, const char *reason)
{
~>    dprintf(fd, reason);
}
