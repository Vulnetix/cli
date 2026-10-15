#include <cstdlib>
#include <string>

std::string home_dir()
{
    const char *h = std::getenv("HOME");
    std::string home = h ? h : "/tmp";
    return home;
}
