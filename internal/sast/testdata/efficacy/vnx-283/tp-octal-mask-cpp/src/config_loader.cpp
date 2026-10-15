#include <sys/stat.h>
#include <string>

bool ConfigLoader::IsSafe(const std::string &file) const {
    struct stat info;
    if (::stat(file.c_str(), &info) != 0) return false;
~>    return (info.st_mode & 022) == 0;
}

bool ConfigLoader::CheckFd(int fd) const {
    struct stat *p = &cache_;
    fstat(fd, p);
~>    if (p->st_mode & 0077) return false;
    return true;
}
