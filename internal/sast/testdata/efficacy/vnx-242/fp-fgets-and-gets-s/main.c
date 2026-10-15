#include <stdio.h>

int main(void) {
    char name[64];
    if (fgets(name, sizeof name, stdin) == NULL)
        return 1;
    gets_s(name, sizeof name);
    fgetws(wname, 64, stdin);
    return 0;
}
