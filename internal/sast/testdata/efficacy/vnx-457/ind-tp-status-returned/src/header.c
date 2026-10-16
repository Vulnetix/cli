#include "header.h"

int parse_header(const unsigned char *p, struct hdr *h)
{
    int err;

    if (p == NULL || h == NULL)
        goto out;
    h->version = p[0];
    h->flags = p[1];
out:
~>    return err;
}
