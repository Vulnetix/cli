#include <stdio.h>

int read_pair(FILE *fp, const char *line) {
    int a, b;
    char name[32];
~>    scanf("%d %d", &a);
~>    fscanf(fp, "%31s %d", name);
~>    sscanf(line, "%d,%d", &a, &b, name);
~>    if (sscanf(line, "%d:%s", &a) != 2) {
        return -1;
    }
    return a + b;
}
