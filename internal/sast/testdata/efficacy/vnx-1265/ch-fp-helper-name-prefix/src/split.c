#include <stdio.h>
#include <string.h>

static int split(char *s)
{
    char *t = strtok(s, " ");
    int n = 0;
    while (t) {
        n++;
        t = strtok(NULL, " ");
    }
    return n;
}

static int split_count(const char *s)
{
    int n = 0;
    for (; *s; s++) {
        if (*s == ' ') n++;
    }
    return n;
}

void report(char *lines)
{
    char *l = strtok(lines, "\n");
    while (l != NULL) {
        printf("%d\n", split_count(l));
        my_split(l);
        l = strtok(NULL, "\n");
    }
    printf("%d\n", split(lines));
}
