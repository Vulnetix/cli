#include <unistd.h>
#include <stdexcept>

void Session::lower(uid_t uid, gid_t gid)
{
    if (::seteuid(uid) == -1)
        throw std::runtime_error("seteuid");
~>    if (::setegid(gid) == -1)
        throw std::runtime_error("setegid");
}
