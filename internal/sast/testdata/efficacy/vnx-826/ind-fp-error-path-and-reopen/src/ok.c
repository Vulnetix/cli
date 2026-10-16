#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

int f(const char *path, int sock)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    fclose(fp);
    fp = fopen("other", "r");
    fgets((char *)path, 4, fp);

    int fd = sock;
    close(fd);
    fd = -1;
    if (fd >= 0) write(fd, "x", 1);

    close(sock);
    return 0;
    send(sock, "x", 1, 0);
}

int g(int fd, int ok)
{
    if (ok) {
        close(fd);
    } else {
        write(fd, "x", 1);
    }
    return 0;
}
