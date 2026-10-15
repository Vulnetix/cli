#include <string.h>

struct request { const char *host; const char *path; };
struct entry { char host[64]; char path[256]; };

void store(struct entry *e, const struct request *req)
{
~>    memcpy(e->host,
           req->host,
           strlen(req->host) + 1);
    size_t plen;
    plen = strlen(req->path);
~>    strncat(e->path, req->path, plen);
}
