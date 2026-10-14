#include <stdlib.h>
#include <string.h>

#define NAME_MAX_LEN 64

struct user {
    char name[NAME_MAX_LEN];
};

int set_name(struct user *u, const char *name)
{
    if (strlen(name) >= sizeof(u->name))
        return -1;
    strcpy(u->name, name);
    return 0;
}

char *dup_string(const char *s)
{
    char *p = malloc(strlen(s) + 1);

    if (p == NULL)
        return NULL;
    strcpy(p, s);
    return p;
}

char *join(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);
    char *out = malloc(la + lb + 2);

    if (out == NULL)
        return NULL;

    strcpy(out, a);
    strcat(out, "/");
    strcat(out, b);
    return out;
}

void label(char *dst, size_t dstlen, const char *msg, const char *who)
{
    char line[80];

    if (strlen(msg) + strlen(who) + 2 > sizeof(line))
        return;
    sprintf(line, "%s: %s", who, msg);
    copy_out(dst, dstlen, line);
}
