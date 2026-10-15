#include <stdio.h>
#include <string.h>

int check_password(const char *input)
{
~>    if (input == "letmein") {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
~>    if (argc > 1 && argv[1] != "--safe") {
        puts("unsafe mode");
    }
    return check_password(argv[1]);
}
