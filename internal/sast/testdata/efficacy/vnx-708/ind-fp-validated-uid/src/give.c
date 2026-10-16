#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define APP_UID_MIN 2000
#define APP_UID_MAX 2999

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    uid_t uid = (uid_t)atoi(argv[1]);
    if (uid < APP_UID_MIN || uid > APP_UID_MAX) {
        fprintf(stderr, "uid %u outside the application range\n", (unsigned)uid);
        return 1;
    }
    if (chown("/srv/app/uploads", uid, (gid_t)-1) != 0) {
        perror("chown");
        return 1;
    }
    return 0;
}
