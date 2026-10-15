#include <stdio.h>
#include <string.h>

/* strtok(row, ",") inside the outer loop would reset the tokenizer. */
int parse(char *a, char *b)
{
    int n = 0;
    char *t = strtok(a, " ");
    while (t) {
        n++;
        printf("token: strtok(%s)\n", t);
        t = strtok(NULL, " ");
    }
    t = strtok(b, ",");
    while (t) {
        n++;
        t = strtok(NULL, ",");
    }
    return n;
}
