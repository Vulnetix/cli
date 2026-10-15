#include <cstdio>

bool Loader::open(const std::string &path)
{
    FILE *fp = std::fopen(path.c_str(), "rb");
    if (!fp)
        return false;
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return false;
    size_t got = fread(buf_, 1, sizeof buf_, fp);
    if (got == 0)
        return false;
    int delta = compare(a, b);
    if (delta < 0)
        swap(a, b);
    ssize_t w = ::write(fd, buf_, got);
    if (w == -1)
        return false;
    return true;
}
