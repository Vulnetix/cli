#include <unistd.h>
#include <string>

std::string self_path()
{
    char target[4096];
    ssize_t n = readlink("/proc/self/exe", target, sizeof(target) - 1);
~>    target[n] = '\0';
    return std::string(target);
}
