#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/tmp/chown-fixture";
    uid_t uid = (uid_t)atoi(getenv("TEST_UID"));
    assert(chown(path, uid, (gid_t)-1) == 0);
    return 0;
}
