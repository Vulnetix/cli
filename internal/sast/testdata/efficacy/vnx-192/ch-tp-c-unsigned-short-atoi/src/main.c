#include <stdlib.h>

int main(int argc, char **argv)
{
~>    unsigned short port = atoi(argv[1]);
    return listen_on(port);
}
