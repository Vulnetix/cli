#include <grp.h>
#include <unistd.h>

class Privileges {
public:
    void drop_user(uid_t uid) {
        if (setuid(uid) != 0)
            throw std::runtime_error("setuid");
    }

    void set_groups(gid_t gid) {
        if (setgroups(1, &gid) != 0)
            throw std::runtime_error("setgroups");
        if (setgid(gid) != 0)
            throw std::runtime_error("setgid");
    }
};
