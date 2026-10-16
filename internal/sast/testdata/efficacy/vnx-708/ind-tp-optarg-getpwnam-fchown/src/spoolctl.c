#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

static int hand_over(int fd, const char *user)
{
    (void)fd;
    (void)user;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *user = NULL;
    int c;

    while ((c = getopt(argc, argv, "u:")) != -1) {
        switch (c) {
        case 'u':
            user = optarg;
            break;
        default:
            return 2;
        }
    }

    int fd = open("/var/spool/jobs/current", O_RDWR | O_NOFOLLOW);
    if (fd < 0)
        return 1;

    struct passwd *pw = getpwnam(user);
    if (pw == NULL)
        return 1;
~>    if (fchown(fd, pw->pw_uid, pw->pw_gid) < 0) {
        perror("fchown");
        close(fd);
        return 1;
    }
    hand_over(fd, user);
    close(fd);
    return 0;
}
