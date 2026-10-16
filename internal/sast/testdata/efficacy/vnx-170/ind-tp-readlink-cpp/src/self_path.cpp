#include <climits>
#include <string>
#include <unistd.h>

std::string executable_path()
{
    char target[PATH_MAX];
~>    ssize_t n = readlink("/proc/self/exe", target, sizeof(target));
    if (n < 0) {
        return {};
    }
    return std::string(target);
}
