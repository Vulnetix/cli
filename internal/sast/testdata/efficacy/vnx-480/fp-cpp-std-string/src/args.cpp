#include <string>

bool help(const std::string &arg)
{
    return arg == "--help" || arg != "-h";
}
