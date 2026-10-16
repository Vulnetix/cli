#include <string.h>

void two_passes(char *a, char *b)
{
    char *t = strtok(a, ",");
    while (t) {
        t = strtok(NULL, ",");
    }
    t = strtok(b, ";");
    while (t) {
        t = strtok(NULL, ";");
    }
}
