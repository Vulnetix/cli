#include <unistd.h>
#include <pwd.h>
#include <err.h>

void run_unprivileged(const struct passwd *pw) {
    if (setgid(pw->pw_gid) == -1) err(1, "setgid");
~>    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
        err(1, "setresuid");
}
