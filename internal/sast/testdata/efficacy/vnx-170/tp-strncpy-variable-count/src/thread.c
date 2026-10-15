#include <string.h>

int get_thread_name(char *buf, size_t limit, const char *name)
{
~>    strncpy(buf, name, limit);
    return 0;
}

void set_tag(char *tag, const char *src)
{
~>    strncpy(tag, src, 8);
}
