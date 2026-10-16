#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct rec { char a[8]; int n; };

void ok(int fd, const char *user, struct rec *r, const char *p)
{
    char name[16];
    char path[256];
    char body[512];
    snprintf(name, sizeof(name), "%s", user);
    read(fd, body, sizeof(body));
    memcpy(name, path, sizeof(path) < sizeof(name) ? sizeof(path) : sizeof(name));
    memcpy(path, body, sizeof(body));
    memset(r, 0, sizeof(*r));
    memset(r, 0, sizeof(struct rec));
    strncpy(p2, p, sizeof(r->a));
    getcwd(path, sizeof path);
}
