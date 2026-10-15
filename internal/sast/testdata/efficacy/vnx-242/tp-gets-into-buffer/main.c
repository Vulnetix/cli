#include <stdio.h>

int main(void) {
    char name[64];
    printf("name: ");
~>    gets(name);
~>    if (gets (name) == NULL)
        return 1;
    printf("hello %s\n", name);
    return 0;
}
