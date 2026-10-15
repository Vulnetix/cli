#include "proto.h"

int frame_len(int type, int *out)
{
    int len;
    int flags;
    len = HEADER_LEN;
    init_flags(&flags);
    switch (type) {
    case T_DATA:
        len = DATA_LEN;
        flags = 1;
        break;
    case T_ACK:
        len = ACK_LEN;
        flags = 2;
        break;
    }
    *out = flags;
    return len;
}
