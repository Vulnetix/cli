#include <cstdlib>

long parse_limit(const char *arg)
{
~>    return std::strtol(arg, nullptr, 0);
}
