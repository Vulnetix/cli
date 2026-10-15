#include <stdlib.h>
#include <string.h>

struct msg {
    char *data;
    size_t off;
};

void drop_header(char *packet, size_t hdr)
{
~>    free(packet + hdr);
}

void release(struct msg *m)
{
~>    free(m->data+m->off);
}

void release_tail(char *buf)
{
~>    free(&buf[4]);
~>    free((void *)(buf + 1));
}

void skip_and_free(char *p)
{
~>    free(++p);
}
