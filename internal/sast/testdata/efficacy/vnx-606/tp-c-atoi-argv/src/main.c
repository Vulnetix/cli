#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int rounds = atoi(argv[1]);
    int i = 0;
~>    while (i < rounds) {
        puts("tick");
        i++;
    }
    long n = strtol(getenv("REPEAT"), NULL, 10);
~>    for (long j = 0; j <= n; ++j) {
        puts("again");
    }
    return 0;
}
