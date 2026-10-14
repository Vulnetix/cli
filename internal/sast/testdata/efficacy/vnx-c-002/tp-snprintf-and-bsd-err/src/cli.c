#include <err.h>
#include <stdio.h>
#include <wchar.h>

void fail(const char *path, const char *reason, const wchar_t *wmsg)
{
    char buf[128];
    wchar_t wbuf[128];

~>    snprintf(buf, sizeof buf, reason);
~>    swprintf(wbuf, 128, wmsg);
~>    wprintf(wmsg);
~>    warnx(reason);
~>    warn(path);
~>    errx(2, reason);
~>    err(1, path);
}
