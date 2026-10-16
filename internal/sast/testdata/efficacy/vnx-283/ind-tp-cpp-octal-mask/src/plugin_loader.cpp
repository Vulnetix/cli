#include <sys/stat.h>
#include <string>

namespace plugins {

static bool is_safe_to_load(const std::string& so_path)
{
    struct stat info {};
    if (::lstat(so_path.c_str(), &info) != 0) {
        return false;
    }
~>    return (info.st_mode & 022) == 0;
}

void* Loader::open(const std::string& so_path)
{
    if (!is_safe_to_load(so_path)) {
        throw LoadError("refusing writable plugin " + so_path);
    }
    return ::dlopen(so_path.c_str(), RTLD_NOW);
}

}  // namespace plugins
