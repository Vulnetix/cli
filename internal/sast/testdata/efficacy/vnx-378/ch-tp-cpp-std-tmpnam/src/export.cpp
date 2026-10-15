#include <cstdio>
#include <fstream>
#include <string>

std::string exportReport(const std::string &body)
{
    char buf[L_tmpnam];
~>    if (!std::tmpnam(buf)) {
        return {};
    }
    std::ofstream out(buf);
    out << body;
    return buf;
}

std::string scratchDir()
{
~>    char *dir = ::tempnam("/var/tmp", "rep");
    std::string s(dir);
    free(dir);
    return s;
}
