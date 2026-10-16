#include <stdint.h>
#include "proto.h"

int proto_step(struct conn *c, uint8_t opcode)
{
    switch (opcode) {
    case OP_HELLO:
        c->state = ST_GREETED;
        c->retries = 0;
        break;
~>    case OP_AUTH:
        c->state = ST_AUTHED;
        audit_log(c, "auth ok");
    case OP_DATA:
        c->bytes_in += c->frame_len;
        break;
    case OP_BYE:
        c->state = ST_CLOSED;
        return 0;
    default:
        return -1;
    }
    return 1;
}
