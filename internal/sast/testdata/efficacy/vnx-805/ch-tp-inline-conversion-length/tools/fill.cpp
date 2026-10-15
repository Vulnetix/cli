#include <cstring>
#include <cstdlib>
#include <string>

void fill(char *out, const char *src, int argc, char **argv)
{
    if (argc < 3)
        return;
~>    std::memcpy(out, src, std::atoi(argv[2]));
}

void pad(char *out, const std::string &count)
{
~>    memset(out, ' ', std::stoul(count));
}
