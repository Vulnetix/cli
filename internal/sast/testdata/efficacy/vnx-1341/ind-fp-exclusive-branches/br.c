#include <stdlib.h>
void done(char *p, int ok)
{
    if (ok) {
        free(p);
    } else {
        log_fail();
        free(p);
    }
}
int early(char *p)
{
    if (!check(p)) {
        free(p);
        return -1;
    }
    free(p);
    return 0;
}
