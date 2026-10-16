#include <stdio.h>
#include <unistd.h>

void rotate(const char *a, const char *b)
{
    FILE *fp = fopen(a, "r");
    fclose(fp);
    fp = fopen(b, "r");
    fclose(fp);

    int fd = open(a, 0);
    close(fd);
    fd = -1;
    close(fd);
}

void two_files(FILE *in, FILE *out)
{
    fclose(in);
    fclose(out);
}
