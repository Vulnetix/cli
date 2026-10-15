#include <sys/socket.h>
#include <stdio.h>

int start(struct agent *a)
{
~>    a->ctrl_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (a->ctrl_sock < 0)
        return -1;
    FILE *p = popen(a->status_cmd, "r");
    if (p)
        pclose(p);
    return 0;
}
