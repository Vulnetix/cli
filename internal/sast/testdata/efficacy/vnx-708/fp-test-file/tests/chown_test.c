#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    return chown(argv[1], atoi(argv[2]), atoi(argv[3]));
}
