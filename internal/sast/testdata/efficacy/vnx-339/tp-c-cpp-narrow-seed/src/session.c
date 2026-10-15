#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void new_session_id(char *session_id, size_t n, unsigned int seed) {
~>    srand((unsigned short) seed);
    snprintf(session_id, n, "%08x", rand());
}

void new_otp(char *otp, size_t n, unsigned int seed) {
~>    srand(seed % 1000);
    snprintf(otp, n, "%06d", rand() % 1000000);
}
