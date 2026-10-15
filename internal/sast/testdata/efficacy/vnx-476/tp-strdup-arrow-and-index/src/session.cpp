#include <cstdlib>
#include <cstring>

struct session { char *name; int id; };

session *new_session(const char *name)
{
    session *s = static_cast<session *>(malloc(sizeof(session)));
~>    s->id = 0;
    s->name = strdup(name);
~>    s->name[0] = 'S';
    return s;
}

void grow(char **buf, size_t n)
{
    char *tmp = realloc(*buf, n);
~>    tmp[n - 1] = 0;
    *buf = tmp;
}
