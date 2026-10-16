#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void copy_body(const uint8_t *frame, uint8_t *body, size_t cap)
{
    uint16_t want = ntohs(*(const uint16_t *)frame);
    size_t n = MIN((size_t)want, cap);
    memcpy(body, frame + 2, n);
}
