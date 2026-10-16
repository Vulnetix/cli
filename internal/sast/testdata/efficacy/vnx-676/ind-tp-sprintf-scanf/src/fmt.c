#include <stdio.h>

void greet(const char *who, int n) {
    char out[40];
    char word[16];
~>    sprintf(out, "hello %s, you have %d", who, n);
~>    scanf("%s", word);
    puts(out);
}
