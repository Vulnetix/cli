#include <unistd.h>
#include <string>

std::string current_dir()
{
    char cwd[1024];
~>    if (::getwd(cwd) == nullptr) {
        return std::string();
    }
    return std::string(cwd);
}
