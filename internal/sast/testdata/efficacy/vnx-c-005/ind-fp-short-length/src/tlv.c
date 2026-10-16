#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

unsigned char *read_tlv_value(const unsigned char *p)
{
    uint16_t len = ntohs(*(const uint16_t *)(p + 1));
    unsigned char *val = malloc(len + 1);
    if (val == NULL)
        return NULL;
    memcpy(val, p + 3, len);
    val[len] = 0;
    return val;
}
