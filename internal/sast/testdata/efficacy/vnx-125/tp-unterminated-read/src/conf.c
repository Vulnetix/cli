#include <stdio.h>
#include <string.h>
#include <unistd.h>

void load(int fd)
{
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0)
        return;
~>    size_t len = strlen(buf);
~>    printf("config: %s\n", buf);
}

void load_file(FILE *fp)
{
    char data[128];
    fread(data, 1, sizeof data, fp);
~>    char *copy = strdup(data);
    use(copy);
}
