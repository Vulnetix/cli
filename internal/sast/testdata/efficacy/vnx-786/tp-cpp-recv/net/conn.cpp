#include <sys/socket.h>
#include <string>

std::string Conn::Recv() {
  char msg[256];
  auto got = recv(sock_, msg, sizeof msg - 1, 0);
~>  msg[got] = '\0';
  return std::string(msg);
}
