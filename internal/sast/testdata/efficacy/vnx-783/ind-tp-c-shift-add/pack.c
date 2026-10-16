#include <stdint.h>

uint16_t be16(const uint8_t *p) {
~>    uint16_t v = p[0] << 8 + p[1];
    return v;
}
