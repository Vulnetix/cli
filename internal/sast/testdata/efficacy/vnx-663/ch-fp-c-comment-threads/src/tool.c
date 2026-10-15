/* Single-threaded tool: we deliberately avoid pthread_create here. */
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    char *tok = strtok(argv[1], ",");
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    return tok != NULL && t != NULL;
}
