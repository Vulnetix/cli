#include <string.h>
#include <stdio.h>

void prompt(void) {
    char password[64];
    memset(password, 0, sizeof password);
    fgets(password, sizeof password, stdin);
    use(password);
    memset(password, 0, sizeof password);
    puts(password);
}

void fill(char *key) {
    memset(key, 0xAA, 32);
    free(key);
}
