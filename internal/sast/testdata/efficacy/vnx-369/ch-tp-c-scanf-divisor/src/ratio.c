#include <stdio.h>

int main(void) {
    int total = 100;
    int parts;
    if (scanf("%d", &parts) != 1) {
        return 1;
    }
~>    printf("%d\n", total / parts);
    return 0;
}
