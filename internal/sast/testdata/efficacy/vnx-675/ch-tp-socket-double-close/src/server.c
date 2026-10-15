#include <unistd.h>

int serve(int sockfd)
{
    char buf[256];
    read(sockfd, buf, sizeof buf);
    close(sockfd);
    fprintf(stderr, "done\n");
    if (verbose) {
        puts("bye");
    }
~>    close(sockfd);
    return 0;
}
