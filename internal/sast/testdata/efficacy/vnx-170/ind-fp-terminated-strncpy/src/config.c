#include <string.h>

struct config {
    char name[64];
};

void config_set_name(struct config *c, const char *src)
{
    strncpy(c->name, src, sizeof(c->name));
    c->name[sizeof(c->name) - 1] = '\0';
}

void copy_field(char *dst, size_t dstlen, const char *src)
{
    strncpy(dst, src, dstlen);
    dst[dstlen - 1] = '\0';
}
