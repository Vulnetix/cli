#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
~>    if (setgid(0) != 0) {
        perror("setgid");
        return 1;
    }
~>    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }
    execl("/bin/sh", "sh", "-c", argv[1], (char *)NULL);
    return 0;
}
