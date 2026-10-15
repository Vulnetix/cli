#include <grp.h>
#include <pwd.h>
#include <system_error>
#include <unistd.h>

void drop_to(const passwd &pw) {
    if (initgroups(pw.pw_name, pw.pw_gid) != 0)
        throw std::system_error(errno, std::generic_category(), "initgroups");
    if (setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid) != 0)
        throw std::system_error(errno, std::generic_category(), "setresgid");
    if (setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid) != 0)
        throw std::system_error(errno, std::generic_category(), "setresuid");
}
