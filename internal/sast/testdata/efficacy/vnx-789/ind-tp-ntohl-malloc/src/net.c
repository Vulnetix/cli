#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>

unsigned char *read_payload(uint32_t raw)
{
    uint32_t len = ntohl(raw);
~>    unsigned char *payload = malloc(len);
    return payload;
}
