#include "frame.h"

int frame_header_len(enum frame_kind kind)
{
    int hdr = 0;

    switch (kind) {
    case FRAME_DATA:    hdr = 9; break;
    case FRAME_HEADERS: hdr = 14; break;
    }
    return hdr;
}
