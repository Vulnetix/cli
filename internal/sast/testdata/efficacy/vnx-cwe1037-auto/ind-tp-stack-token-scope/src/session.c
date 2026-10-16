#include <string.h>

int refresh(struct conn *c)
{
    unsigned char session_token[48];
    fetch_token(c, session_token, sizeof session_token);
    int rc = send_token(c, session_token);
~>    memset(session_token, 0, sizeof(session_token));
    return rc;
}
