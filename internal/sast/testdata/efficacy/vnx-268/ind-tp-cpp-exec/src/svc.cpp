#include <string>
#include <unistd.h>

void restart_service(const std::string &svc)
{
~>    ::execlp("doas", "doas", "/usr/sbin/rcctl", "restart", svc.c_str(), (char *)nullptr);
}
