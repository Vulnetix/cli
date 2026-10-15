#include <stdio.h>
#include <string.h>

void dump(char *buf)
{
    char *w = strtok(buf, " ");
    while (w != NULL) {
        /* char *x = strtok(w, "-"); would break the outer loop */
        puts("never call strtok(w, \"-\") here");
        puts(w);
        w = strtok(NULL, " ");
    }
}
