#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
    printf("running %s\n", argv[0]);
    if (chown("/run/app.pid", getuid(), getgid()) != 0) {
        perror("chown");
    }
    fchown(3, geteuid(), (gid_t)-1);
    return 0;
}
