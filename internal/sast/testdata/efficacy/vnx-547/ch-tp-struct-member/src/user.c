#include <string.h>

struct user {
    int id;
    char name[32];
};

void set_name(struct user *u, const char *src)
{
~>    strncpy(u->name, src, 32);
}
