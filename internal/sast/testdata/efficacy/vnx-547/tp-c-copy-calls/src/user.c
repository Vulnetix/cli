#include <string.h>
#include <unistd.h>

struct user { int id; };

void load(int fd, const char *src) {
    char name[64];
    unsigned char buf[4096];
    char out[128];
~>    strncpy(name, src, 64);
~>    ssize_t n = read(fd, buf, 4096);
~>    snprintf(out, 128, "%s:%zd", name, n);
~>    memcpy(name, src,
           64);
}
