#include <cstdio>

void Server::log(const std::string &host, int port) {
~>    std::printf("listening on %s:%d\n", host.c_str());
~>    std::sscanf(spec.c_str(), "%d", &port, &extra);
}
