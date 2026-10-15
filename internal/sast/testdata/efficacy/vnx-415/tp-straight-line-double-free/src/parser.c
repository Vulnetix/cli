#include <stdlib.h>
#include <string.h>

int parse_header(const char *in, size_t len)
{
    char *buf = malloc(len + 1);
    if (buf == NULL)
        return -1;
    memcpy(buf, in, len);
    buf[len] = '\0';
    int rc = validate(buf);
    free(buf);
    if (rc != 0) {
        log_error("invalid header");
    }
~>  free(buf);
    return rc;
}
