#include <cstdlib>
#include <cstring>
#include <string>

std::size_t home_length()
{
    const char *home = std::getenv("HOME");
~>    return std::strlen(home);
}
