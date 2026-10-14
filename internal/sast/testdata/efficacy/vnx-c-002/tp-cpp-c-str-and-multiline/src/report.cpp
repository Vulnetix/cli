#include <cstdio>
#include <string>

void report(const std::string &name, const std::string &message)
{
~>    std::printf(name.c_str());
~>    fprintf(stderr,
            message.c_str());
~>    std::fprintf(stdout, (message + "\n").c_str());
}
