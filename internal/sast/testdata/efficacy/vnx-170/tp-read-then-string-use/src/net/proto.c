#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int read_port(int fd)
{
    char buf[16];
~>    if (read(fd, buf, sizeof(buf)) < 0)
        return -1;
    return atoi(buf);
}

void greet(int sock)
{
    char name[64];
    ssize_t n;

~>    n = recv(sock, name, sizeof(name), 0);
    if (n <= 0)
        return;
    printf("client says %s\n", name);
}

size_t header_len(FILE *fp)
{
    char hdr[256];
~>    fread(hdr, 1, sizeof hdr, fp);
    return strlen(hdr);
}
