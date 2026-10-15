#include <string.h>
#include <stdlib.h>
void t(void) {
    char *password = malloc(8);
    memset(password, 0, 8);
    free(password);
}
