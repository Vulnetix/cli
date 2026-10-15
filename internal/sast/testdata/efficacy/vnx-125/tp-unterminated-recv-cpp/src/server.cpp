#include <cstring>
#include <string>
#include <sys/socket.h>

std::string handle(int sock)
{
    char req[1024];
    int got = recv(sock, req, sizeof(req), 0);
    if (got < 0)
        return "";
~>    if (strstr(req, "GET ") == req)
        return "get";
~>    return std::string(req);
}
