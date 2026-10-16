#include <cstdio>

struct conn {
    char host[64];
    char url[512];
};

void set_host(conn *c, const char *u)
{
~>    std::snprintf(c->host, sizeof(c->url), "%s", u);
}
