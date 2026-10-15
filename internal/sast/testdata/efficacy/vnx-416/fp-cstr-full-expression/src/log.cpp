#include <cstdio>
#include <string>

void log_port(int port, const std::string &host)
{
    std::printf("%s:%s\n", host.c_str(), std::to_string(port).c_str());
    send_line((host + ":" + std::to_string(port)).c_str());
    std::string label = std::to_string(port);
    const char *p = label.c_str();
    use(p);
}
