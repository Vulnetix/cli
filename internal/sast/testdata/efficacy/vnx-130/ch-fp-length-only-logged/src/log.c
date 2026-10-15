#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void note(unsigned char out[32], const unsigned char *p)
{
    uint16_t len = ntohs(*(const uint16_t *)p);
    printf("record of %u bytes\n", len);
    memcpy(out, p + 2, sizeof(out[0]) * 32);
}
