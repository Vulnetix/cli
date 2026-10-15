#include <string.h>

struct sbuf { char *data; size_t len; };

void drop_first(char *buf, size_t len)
{
~>    memcpy(buf, buf + 1, len - 1);
}

void strip_prefix(char *path)
{
~>    strcpy(path, path + 2);
~>    strncpy(&path[0], &path[1], strlen(path));
}

void double_name(char *name)
{
~>    strcat(name, name);
}

void shift(struct sbuf *s, size_t off, size_t n)
{
~>    memcpy(s->data + off, (const char *)s->data, n);
}
