#include <cstdlib>
#include <string>

std::string config_dir()
{
~>    std::string home(std::getenv("HOME"));
~>    std::string xdg = getenv("XDG_CONFIG_HOME");
    return xdg.empty() ? home + "/.config" : xdg;
}
