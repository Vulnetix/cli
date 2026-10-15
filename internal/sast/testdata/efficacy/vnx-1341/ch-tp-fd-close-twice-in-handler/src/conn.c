#include <unistd.h>
#include <stdio.h>

void handle_client(int client_fd)
{
    char buf[512];
    ssize_t n = read(client_fd, buf, sizeof(buf));
    if (n <= 0) {
        perror("read");
        close(client_fd);
    }
    write(STDOUT_FILENO, buf, n > 0 ? (size_t)n : 0);
~>    close(client_fd);
}
