#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int roll_die(void)
{
    return rand() % 6 + 1;
}

int main(void)
{
    srand((unsigned) time(NULL));
    printf("You rolled %d and %d\n", roll_die(), roll_die());
    return 0;
}
