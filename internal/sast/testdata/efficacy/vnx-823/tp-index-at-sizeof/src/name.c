#include <string.h>

void copy_name(char *dst_out, const char *src)
{
    char buf[64];
    strncpy(buf, src, sizeof(buf));
~>    buf[sizeof(buf)] = '\0';
    char tag[8];
    memcpy(tag, src, sizeof tag);
~>    tag[ sizeof tag ] = 0;
    strcpy(dst_out, buf);
}
