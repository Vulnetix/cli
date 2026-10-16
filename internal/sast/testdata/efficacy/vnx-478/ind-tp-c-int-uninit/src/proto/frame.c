#include <stdint.h>
#include "frame.h"

int frame_header_len(enum frame_kind kind, const uint8_t *buf)
{
    int hdr;

~>    switch (kind) {
    case FRAME_DATA:    hdr = 9; break;
    case FRAME_HEADERS: hdr = 14; break;
    case FRAME_PING:    hdr = 17; break;
    }

    return hdr + buf[0];
}
