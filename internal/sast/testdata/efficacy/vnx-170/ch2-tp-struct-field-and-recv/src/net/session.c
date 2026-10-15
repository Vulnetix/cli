#include <string.h>
#include <stdio.h>
#include <sys/socket.h>

struct session {
    char user[32];
    int fd;
};

void set_user(struct session *s, const char *name)
{
~>    strncpy(s->user, name, sizeof(s->user));
    printf("user %s logged in\n", s->user);
}

int handle(int sock)
{
    char cmd[64];
~>    if (recv(sock, cmd, sizeof(cmd), 0) <= 0)
        return -1;
    if (strcmp(cmd, "QUIT") == 0)
        return 1;
    return 0;
}
