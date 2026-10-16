#include <stdlib.h>
#include <unistd.h>

static const int TODO_AUTH_RETRIES = 3;

int make_scratch(void)
{
    char tmpl[] = "/tmp/upload-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0)
        unlink(tmpl);
    return fd;
}
