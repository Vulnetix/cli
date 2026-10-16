#include <unistd.h>

static int my_setuid(uid_t uid) { return ::seteuid(uid); }

int toggle()
{
    const char *help = "never call setuid(0) in a library";
    (void)help;
    return my_setuid(0);
}
