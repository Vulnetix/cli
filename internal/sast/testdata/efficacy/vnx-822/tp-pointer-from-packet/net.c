#include <sys/socket.h>

struct node { struct node *next; int v; };

void serve(int sock) {
    char buf[256];
    recv(sock, buf, sizeof(buf), 0);
~>    struct node *next = *(struct node **)(buf + 8);
    next->v = 0;
}
