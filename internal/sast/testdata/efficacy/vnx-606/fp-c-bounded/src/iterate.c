#include <stdio.h>
#include <stdlib.h>
#define MAX_ITEMS 1000

void iterate_requested(void) {
    unsigned int num;
    scanf("%u", &num);
    if (num > MAX_ITEMS) {
        return;
    }
    for (unsigned int i = 0; i < num; i++) {
        puts("x");
    }
}

int main(int argc, char **argv) {
    int rounds = atoi(argv[1]);
    for (int i = 0; i < rounds && i < MAX_ITEMS; i++) {
        puts("tick");
    }
    return 0;
}
