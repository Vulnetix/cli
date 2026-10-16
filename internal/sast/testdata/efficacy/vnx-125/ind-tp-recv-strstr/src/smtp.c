#include <string.h>
#include <sys/socket.h>

int expect_ok(int s)
{
    char reply[1024];
    int r = recv(s, reply, sizeof(reply), 0);
    if (r <= 0)
        return -1;
~>    if (strstr(reply, "250 OK") != NULL)
        return 0;
    return 1;
}
