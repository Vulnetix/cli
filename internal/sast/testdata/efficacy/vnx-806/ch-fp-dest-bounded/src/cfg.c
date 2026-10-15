#include <string.h>

struct cfg { char name[32]; };

void set(struct cfg *c, const char *src)
{
    strncpy(c->name, src, sizeof(c->name) - 1);
    c->name[sizeof(c->name) - 1] = '\0';
    /* strncpy(c->name, src, strlen(src)); would overflow */
    const char *msg = "memcpy(dst, src, strlen(src))";
    (void)msg;
}
