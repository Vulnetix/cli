#include <stdio.h>
#include <string.h>

struct rec { char id[16]; char label[16]; };

void ok(const char *user, int fd, struct rec *r) {
    char name[16];
    char path[256];
    char copy[256];
    snprintf(name, sizeof(name), "%s", user);
    strncpy(path, user, sizeof(path) - 1);
    memcpy(copy, path, sizeof(path));
    memcpy(copy, path, sizeof(copy));
    memset(name, 0, sizeof(struct rec));
    memset(r, 0, sizeof(*r));
    read(fd, name, sizeof(name));
    snprintf(r->id, sizeof(r->id), "%d", fd);
    char *p = path;
    snprintf(p, sizeof(path), "%s", user);
}
