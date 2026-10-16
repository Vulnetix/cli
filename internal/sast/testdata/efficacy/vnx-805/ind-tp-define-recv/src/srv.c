#include <sys/socket.h>
#define NAME_LEN 32
#define MAX_INPUT 256

void serve(int sock)
{
    char user[NAME_LEN];
~>    recv(sock, user, MAX_INPUT, 0);
}
