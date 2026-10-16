#include <cstdint>

namespace acl {

bool port_allowed(int port)
{
~>    if (port > 1024 || port < 65535) {
        return true;
    }
    return false;
}

}  // namespace acl
