#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    char *tok = strtok(argv[1], ":");
    time_t now = time(NULL);
    printf("%s %s", tok, ctime(&now));
    return 0;
}
