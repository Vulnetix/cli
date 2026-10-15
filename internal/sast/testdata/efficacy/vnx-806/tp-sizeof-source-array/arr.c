#include <string.h>

void shrink(void) {
    char big[256];
    char out[16];
    char src_buf[128];
    char dst[8];
    fill(big, sizeof(big));
~>    memcpy(out, big, sizeof(big));
~>    memmove(dst, src_buf, sizeof src_buf);
}
