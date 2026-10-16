#include <stdexcept>
#include <string>

namespace net {

void validate_port(int port)
{
~>    if (port > 65535 && port < 1024) {
        throw std::invalid_argument("port out of range: " + std::to_string(port));
    }
}

}  // namespace net
