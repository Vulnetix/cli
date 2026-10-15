#include <pwd.h>
#include <unistd.h>
#include <err.h>

static void drop(struct passwd *pw) {
    if (setgid(pw->pw_gid) == -1)
        err(1, "setgid");
~>    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
        err(1, "setresuid");
}

int main(void) {
    drop(getpwnam("daemon"));
    return serve();
}
