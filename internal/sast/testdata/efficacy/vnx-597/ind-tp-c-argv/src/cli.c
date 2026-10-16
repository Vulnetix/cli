#include <stdio.h>
#include <stdlib.h>

static int run_backup(const char *target, int force);

int main(int argc, char **argv)
{
    int force = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s TARGET [--force]\n", argv[0]);
        return EXIT_FAILURE;
    }
~>    if (argc > 2 && argv[2] == "--force") {
        force = 1;
    }
    return run_backup(argv[1], force);
}

static int check_password(const char *input)
{
~>    return input == "letmein";
}
