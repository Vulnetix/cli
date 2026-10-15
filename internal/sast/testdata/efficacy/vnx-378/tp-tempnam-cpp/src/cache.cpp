#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

std::string CacheFile::reserve(const char *dir)
{
~>    char *raw = ::tempnam(dir, "cache");
    std::string path(raw);
    free(raw);
    std::ofstream out(path);
    return path;
}

std::string CacheFile::reserveWin(char *buf)
{
~>    char *r = _mktemp(buf);
    return std::string(r ? r : "");
}

void CacheFile::threadSafe(char *buf)
{
~>    std::tmpnam(buf);
}
