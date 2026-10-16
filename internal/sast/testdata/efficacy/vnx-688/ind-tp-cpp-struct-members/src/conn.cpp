#include <cstdio>

struct conn { char host[32]; char url[1024]; };

void set(conn *c, const char *u)
{
    char tmp[10];
    char big[200];
~>    std::snprintf(c->host, sizeof(c->url), "%s", u);
~>    memset(tmp, 0, sizeof(big));
    fgets(big, sizeof(big), stdin);
}
