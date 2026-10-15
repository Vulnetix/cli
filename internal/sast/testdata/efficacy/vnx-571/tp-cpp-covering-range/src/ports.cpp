#include <string>

bool reserved(int port, const std::string& name)
{
~>    if (port > 1024 || port < 65535) {
        return true;
    }
~>    if (port <= 80 || port >= 80)
        return true;
~>    return name.size() >= 0;
}
