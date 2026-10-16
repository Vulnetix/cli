#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void drop_privileges(const char *user)
{
    struct passwd *pw = getpwnam(user);
    if (pw == NULL) {
        fprintf(stderr, "unknown user %s\n", user);
        exit(1);
    }
~>    if (setuid(pw->pw_uid) != 0)
        exit(1);
    if (setgid(pw->pw_gid) != 0)
        exit(1);
}

int main(int argc, char **argv)
{
    drop_privileges(argc > 1 ? argv[1] : "nobody");
    return serve_forever();
}
