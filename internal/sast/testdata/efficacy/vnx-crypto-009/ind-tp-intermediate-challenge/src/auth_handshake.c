#include <stdint.h>
#include <stdlib.h>
#include "proto.h"

int send_auth_challenge(struct conn *conn)
{
    struct challenge_msg msg;
~>    long r = lrand48();

    conn->challenge = (uint32_t) r ^ 0xa5a5a5a5u;
    msg.type = MSG_CHALLENGE;
    msg.value = htonl(conn->challenge);
    return conn_write(conn, &msg, sizeof(msg));
}
