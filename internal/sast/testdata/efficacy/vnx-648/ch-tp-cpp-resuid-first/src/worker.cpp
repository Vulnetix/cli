#include <grp.h>
#include <stdexcept>
#include <unistd.h>

void Worker::dropPrivileges(uid_t uid, gid_t gid) {
~>    if (::setresuid(uid, uid, uid) == -1) {
        throw std::runtime_error("setresuid");
    }
    ::setgroups(0, nullptr);
    ::setresgid(gid, gid, gid);
}
