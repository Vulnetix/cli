#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

static FILE *logf;

void rotate_log(const char *path)
{
    fclose(logf);
    logf = fopen(path, "a");
    fprintf(logf, "log rotated\n");
}

void serve(int listener)
{
    int client = accept(listener, NULL, NULL);
    write(client, "hi\n", 3);
    close(client);
    client = accept(listener, NULL, NULL);
    write(client, "again\n", 6);
    close(client);
}

void reset_fd(int *fdp, FILE *out, FILE *in)
{
    close(*fdp);
    *fdp = -1;
    fclose(in);
    fprintf(out, "input closed\n");
}
