#include <sys/socket.h>
#include <unistd.h>

void net(int s)
{
    char cwd[64];
    char packet[1500];
    char host[32];
~>    getcwd(cwd, sizeof(packet));
~>    recv(s, host, sizeof(packet), 0);
~>    gethostname(host, sizeof(cwd));
}
