#include <stdint.h>
#include <string.h>
#include <stdlib.h>

struct header { uint32_t magic; uint32_t len; };

void process(uint8_t *raw, char *text, uint32_t *a)
{
    char buf[64];
    buf[sizeof(buf) - 1] = '\0';
    char *endp = &buf[sizeof(buf)];
    uint8_t *payload = raw + sizeof(struct header);
    uint32_t *past = a + sizeof(a) / sizeof(a[0]);
    char *p = text + sizeof(buf);
    uint8_t *q = (uint8_t *)a + sizeof(*a);
    (void)endp; (void)payload; (void)past; (void)p; (void)q;
}
