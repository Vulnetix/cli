#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void issue_token(char *token, size_t n) {
~>    srand(time(NULL));
    snprintf(token, n, "%08x%08x", rand(), rand());
}
