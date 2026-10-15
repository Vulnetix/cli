#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int fd = open_privileged_device();
    uid_t ruid = getuid();
    if (setgid(getgid()) != 0) abort();
    if (setuid(getuid()) != 0) abort();
    if (setreuid(ruid, ruid) != 0) abort();
    return run(fd, argc, argv);
}
