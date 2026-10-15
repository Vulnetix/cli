#include <cstring>
#include <cstdio>

struct Conn {
    char host[64];
    char url[1024];
};

void Conn_init(Conn *c, const char *u) {
~>    std::snprintf(c->host, sizeof(c->url), "%s", u);
~>    strlcpy(c->host, u, sizeof c->url);
}
