#include <stdio.h>
#include <unistd.h>

void finish(FILE *fp, int keep_open)
{
    if (!keep_open) {
        fclose(fp);
    } else {
        fputs("kept\n", fp);
        fflush(fp);
    }
}

void close_it(int fd)
{
    close(fd);
}

void use_it(int fd)
{
    write(fd, "x", 1);
}

int status(int fd, int mode)
{
    switch (mode) {
    case 0:
        close(fd);
        break;
    case 1:
        write(fd, "1", 1);
        break;
    }
    return 0;
}
