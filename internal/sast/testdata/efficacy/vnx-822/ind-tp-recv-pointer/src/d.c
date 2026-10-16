#include <sys/socket.h>
struct node { struct node *next; int v; };
int walk(int sock)
{
    char buf[64];
    recv(sock, buf, sizeof(buf), 0);
~>    struct node *next = *(struct node **)(buf + 8);
    return next->v;
}
