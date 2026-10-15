#include <stdio.h>

int main(void) {
    char line[128];
~>    while (gets(line) != NULL) {
        puts(line);
    }
    return 0;
}
