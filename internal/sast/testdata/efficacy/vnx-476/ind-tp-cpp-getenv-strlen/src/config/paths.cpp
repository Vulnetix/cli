#include <cstdlib>
#include <cstring>
#include <string>

std::string config_root()
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
~>    size_t n = strlen(xdg);
    return std::string(xdg, n) + "/myapp";
}
