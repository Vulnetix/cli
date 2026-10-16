#include <stdexcept>
#include <unistd.h>

void write_as(uid_t uid, gid_t gid)
{
    if (::seteuid(uid) == -1) throw std::runtime_error("seteuid");
    do_user_io();
    if (::seteuid(0) == -1) throw std::runtime_error("seteuid(0)");
    if (::setegid(gid) == -1) throw std::runtime_error("setegid");
}
