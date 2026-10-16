#include <cstring>

const char *query_string(const char *url)
{
    const char *q = strchr(url, '?');
    return q ? q + 1 : "";
}
