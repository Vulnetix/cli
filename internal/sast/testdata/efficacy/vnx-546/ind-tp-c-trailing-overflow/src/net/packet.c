#include <string.h>
#include "packet.h"

int packet_copy_payload(const struct packet *pkt, unsigned char *out)
{
    unsigned char buf[512];
~>    memcpy(buf, pkt->data, pkt->len); /* XXX: overflow when len exceeds 512 */
    memcpy(out, buf, pkt->len);
    return 0;
}
