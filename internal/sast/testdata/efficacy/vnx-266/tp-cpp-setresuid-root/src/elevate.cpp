#include <unistd.h>
#include <stdexcept>

void become_root()
{
~>    if (::setresgid(0, 0, 0) == -1)
        throw std::runtime_error("setresgid");
~>    if (::setresuid(0, 0, 0) == -1)
        throw std::runtime_error("setresuid");
}

void become_root_legacy()
{
~>    setreuid( 0 , 0 );
}
