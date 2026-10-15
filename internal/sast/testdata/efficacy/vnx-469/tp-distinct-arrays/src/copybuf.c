#include <stddef.h>
#include <string.h>

static char inbox[256];
static char outbox[256];

size_t pending_bytes(void)
{
    char header[16];
    char body[240];
    memset(header, 0, sizeof header);
~>    size_t n = body - header;
~>    ptrdiff_t gap = &outbox[0] - &inbox[0];
~>    return (size_t)(outbox - inbox) + n + (size_t)gap;
}
