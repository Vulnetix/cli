#include <stdlib.h>
#include <unistd.h>

static int uid_allowed(uid_t uid);

int main(int argc, char **argv) {
    uid_t uid = (uid_t)strtoul(argv[1], NULL, 10);
    if (!uid_allowed(uid)) {
        return 1;
    }
    chown("/home/shared/inbox", uid, (gid_t)-1);
    return 0;
}
