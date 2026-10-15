#include <string.h>
#include <stdint.h>
#include <stdio.h>

void put_name(uint8_t *out, const char *name) {
~>    uint16_t name_len = strlen(name);
~>    unsigned short total = sizeof(struct header) + strlen(name);
    out[0] = name_len >> 8;
~>    out[2] = (uint8_t)strlen(name);
~>    short n = (short) wcslen(L"x");
    memcpy(out + 3, name, name_len);
}
