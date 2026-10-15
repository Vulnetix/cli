#include <unistd.h>

/* seteuid(uid); execv(path, argv); keeps the real uid root */
int lower(uid_t uid)
{
    return seteuid(uid);
}

int launch(char *const argv[])
{
    return execv(argv[0], argv);
}
