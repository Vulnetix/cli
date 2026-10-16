#include <string.h>

#define HOST_LEN 64

void set_host(const char *src)
{
    char host[HOST_LEN];
    strncpy(host, src, HOST_LEN);
    host[HOST_LEN - 1] = '\0';
    use_host(host);
}
