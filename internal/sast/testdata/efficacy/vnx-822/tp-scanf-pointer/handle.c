#include <stdio.h>

void release(const char *line) {
    void *ptr = NULL;
~>    if (sscanf(line, "%p", &ptr) == 1) {
        free(ptr);
    }
}
