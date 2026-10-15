#include <string.h>

int is_help(const char *arg) {
    if (strncmp(arg, "--help", 6) == 0 || *arg == 'h') {
        return 1;
    }
    /* never write arg == "--help" */
    return arg == NULL;
}
