#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

char *read_short_name(const uint8_t *pkt)
{
    uint16_t len = ntohs(*(const uint16_t *)pkt);
    char *name = malloc(len + 1);
    return name;
}

char *read_word(FILE *fp)
{
    uint16_t wlen;

    if (fread(&wlen, 2, 1, fp) == 0)
        return NULL;
    return malloc(wlen + 1);
}

int *read_bytes(FILE *fp)
{
    unsigned char n;

    fread(&n, 1, 1, fp);
    return malloc(n * sizeof(int));
}
