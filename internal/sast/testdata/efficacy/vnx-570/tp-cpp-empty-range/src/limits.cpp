#include <vector>
#include <string>

bool in_window(int port, const std::vector<int>& ports, const std::string& s)
{
~>    if (port > 65535 && port < 1024) {
        return false;
    }
~>    if (port <= 10 && port >= 20)
        return false;
~>    if (ports.size() < 0 || s.length() < 0)
        return false;
    return port >= 1024 && port <= 65535;
}
