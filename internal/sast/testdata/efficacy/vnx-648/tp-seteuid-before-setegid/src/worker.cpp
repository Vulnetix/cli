#include <unistd.h>
#include <grp.h>
#include <stdexcept>

void Worker::become(uid_t uid, gid_t gid) {
    if (::initgroups(name_.c_str(), gid) != 0)
        throw std::runtime_error("initgroups");
~>    if (::seteuid(uid) == -1)
        throw std::runtime_error("seteuid");

    if (::setegid(gid) == -1)
        throw std::runtime_error("setegid");
}
