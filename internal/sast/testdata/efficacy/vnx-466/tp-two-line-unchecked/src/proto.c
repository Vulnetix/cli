#include <string.h>

char *reply_body(char *reply)
{
    char *p = strchr(reply + 1, '\r');
    size_t len = (size_t)(p - reply);

    log_len(len);
~>    return p + 2;
}

const char *header_value(const char *line)
{
    const char *sep;

    sep = strpbrk(line, ":=");
~>    return sep + 1;
}

char *find_payload(char *buf, size_t n)
{
    char *end = memrchr(buf, '\n', n);
~>    return end+1;
}
