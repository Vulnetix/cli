#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

int run_as(struct passwd *pw, char *const argv[])
{
    if (seteuid(pw->pw_uid) != 0)
        return -1;
~>    execv(argv[0], argv);
    return -1;
}

FILE *read_as(uid_t uid, const char *cmd)
{
    if (setresuid(-1, uid, -1) != 0)
        return NULL;
~>    return popen(cmd, "r");
}
