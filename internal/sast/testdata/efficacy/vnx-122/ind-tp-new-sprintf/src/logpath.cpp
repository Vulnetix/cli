#include <cstdio>
#include <string>

std::string build_log_path(const char *dir, const char *file)
{
    char *p = new char[256];
~>    sprintf(p, "%s/%s.log", dir, file);
    std::string result(p);
    delete[] p;
    return result;
}
