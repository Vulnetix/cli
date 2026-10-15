#include <err.h>
#include <stdio.h>

static void fail(const char *fmt, int code);

void check(const char *path, int n, int rc)
{
    if (rc < 0)
        err(1, "cannot open %s", path);
    if (n > 3)
        warnx("too many entries: %d", n);
    warn("%s", path);
    errx(2, "giving up");
    fail("exit %d", rc);
    printf("%s=%d\n",
           path,
           n);
    if (fprintf(stderr, "%s: %s\n", path,
                strerror(rc)) < 0)
        return;
}
