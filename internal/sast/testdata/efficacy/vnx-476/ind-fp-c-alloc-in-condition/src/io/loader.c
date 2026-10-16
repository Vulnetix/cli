#include <stdio.h>

int count_lines(const char *path)
{
    FILE *fp;
    char line[512];
    int n = 0;

    if ((fp = fopen(path, "r")) == NULL)
        return -1;
    while (fgets(line, sizeof line, fp))
        n++;
    fclose(fp);
    return n;
}
