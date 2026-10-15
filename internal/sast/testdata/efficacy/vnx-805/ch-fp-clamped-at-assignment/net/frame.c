#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct hdr { uint16_t len; uint8_t body[512]; };

void copy_body(const struct hdr *h, uint8_t *dst, size_t cap)
{
    size_t n = MIN(ntohs(h->len), cap);
    memcpy(dst, h->body, n);

    unsigned long want = strtoul((const char *)h->body, NULL, 10);
    size_t take = want > cap ? cap : want;
    memset(dst, 0, take);
}
