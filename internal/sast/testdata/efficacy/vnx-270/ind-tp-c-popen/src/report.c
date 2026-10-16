#include <stdio.h>
#include <unistd.h>

FILE *open_report(uid_t uid, const char *cmd)
{
    if (setreuid(-1, uid) != 0)
        return NULL;
~>    return popen(cmd, "r");
}
