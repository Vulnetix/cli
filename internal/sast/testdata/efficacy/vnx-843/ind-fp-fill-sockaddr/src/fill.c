#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

void bind_any(struct sockaddr_storage *ss, int port)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = INADDR_ANY;
}
