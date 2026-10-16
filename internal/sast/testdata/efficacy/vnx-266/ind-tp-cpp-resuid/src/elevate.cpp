#include <stdexcept>
#include <unistd.h>

namespace agent {

void become_root()
{
~>    if (::setresuid(0, 0, 0) != 0) {
        throw std::runtime_error("cannot become root");
    }
}

}  // namespace agent
