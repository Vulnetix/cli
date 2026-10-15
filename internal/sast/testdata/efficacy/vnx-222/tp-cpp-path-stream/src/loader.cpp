#include <cstdio>
#include <fstream>
#include <string>

std::string load(const char *root, const char *name)
{
    char path[128];
~>    std::snprintf(path, sizeof path, "%s/%s.conf", root, name);
    std::ifstream in(path);
    return std::string(std::istreambuf_iterator<char>(in), {});
}
