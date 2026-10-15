#include <stdio.h>

static void work(unsigned int k) { (void)k; }

void iterate_requested(void) {
    unsigned int num;
    scanf("%u", &num);
~>    for (unsigned int i = 0; i < num; i++) {
        work(i);
    }
}
