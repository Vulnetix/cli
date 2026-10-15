#include <string.h>

struct rec { char name[32]; };

void set_name(struct rec *r, const char *s)
{
    strncpy(r->name, s, sizeof(r->name) - 1);
    r->name[sizeof(r->name) - 1] = '\0';
}
