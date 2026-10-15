#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
~>    if (setgid(0) != 0)
        return 1;
~>    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }
    execv("/usr/libexec/helper-run", argv);
    return 1;
}
