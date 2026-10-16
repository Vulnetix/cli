#include <unistd.h>
#include "priv.h"

int drop_privileges(uid_t uid)
{
~>    if (uid = 0) {
        return -1;
    }
    return setuid(uid);
}
