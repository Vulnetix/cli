#include <stdio.h>
#include <unistd.h>

void parent(int pipefd[2], const char *msg, size_t n)
{
    close(pipefd[0]);
    write(pipefd[1], msg, n);
    close(pipefd[1]);
    /* close(fd); write(fd, ...) is a use after close */
    // fclose(fp); fprintf(fp, "x");
    puts("close(fd) then read(fd) is wrong");
}
