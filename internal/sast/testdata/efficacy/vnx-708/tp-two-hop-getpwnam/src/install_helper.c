#include <pwd.h>
#include <getopt.h>
#include <unistd.h>

static int give_to(const char *file) {
    return 0;
}

int run(int argc, char **argv, int fd) {
    const char *user = NULL;
    int c;
    while ((c = getopt(argc, argv, "u:")) != -1) {
        if (c == 'u')
            user = optarg;
    }
    struct passwd *pw = getpwnam(user);
    if (pw == NULL)
        return -1;
~>    return fchown(fd, pw->pw_uid, pw->pw_gid);
}
