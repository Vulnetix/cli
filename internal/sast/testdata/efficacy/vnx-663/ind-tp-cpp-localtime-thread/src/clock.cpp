#include <ctime>
#include <string>
#include <thread>

std::string stamp()
{
    std::time_t now = std::time(nullptr);
~>    struct tm *t = localtime(&now);
    char buf[32];
    strftime(buf, sizeof buf, "%F %T", t);
    return buf;
}

void log_async()
{
    std::thread th([] { stamp(); });
    th.join();
}
