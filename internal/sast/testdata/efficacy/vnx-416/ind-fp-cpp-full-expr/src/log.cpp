#include <cstdio>
#include <string>

void log_port(int port, const std::string &host)
{
    std::printf("%s:%s\n", host.c_str(), std::to_string(port).c_str());
    std::string label = std::to_string(port);
    const char *p = label.c_str();
    const char *h = host.data();
    puts(p);
    puts(h);
    // const char *bad = std::to_string(port).c_str();
    const char *msg = "use std::to_string(n).c_str() only inside one expression";
    puts(msg);
}
