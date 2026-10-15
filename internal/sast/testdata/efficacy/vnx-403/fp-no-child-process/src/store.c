#include <fcntl.h>

static int data_fd;

void store_open(const char *path)
{
    data_fd = open(path, O_RDWR | O_CREAT, 0600);
    FILE *f = fopen(path, "r");
}
