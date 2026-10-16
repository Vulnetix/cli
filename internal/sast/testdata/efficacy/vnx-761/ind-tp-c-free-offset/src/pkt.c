#include <stdlib.h>
#include <string.h>

void drop_payload(unsigned char *packet, size_t hdr)
{
~>    free(packet + hdr);
}

void drop_word(char *buf)
{
~>    free(&buf[4]);
}
