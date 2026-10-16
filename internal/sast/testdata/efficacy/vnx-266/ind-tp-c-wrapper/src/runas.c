#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s cmd...\n", argv[0]);
        return 2;
    }
~>    if (setuid(0) == -1) {
        perror("setuid");
        return 1;
    }
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 127;
}
