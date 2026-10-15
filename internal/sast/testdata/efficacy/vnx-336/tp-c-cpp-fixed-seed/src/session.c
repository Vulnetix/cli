#include <stdio.h>
#include <stdlib.h>

void init_rng(void) {
~>    srand(12345);
}

void new_session_id(char *session_id, size_t n) {
    snprintf(session_id, n, "%08x%08x", rand(), rand());
}
