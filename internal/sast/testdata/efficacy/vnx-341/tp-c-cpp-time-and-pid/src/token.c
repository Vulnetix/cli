#include <stdio.h>
#include <time.h>
#include <unistd.h>

void issue_token(char *token, size_t n) {
~>    snprintf(token, n, "%ld-%d", (long) time(NULL), getpid());
}

unsigned long open_session(void) {
~>    unsigned long session_key = time(NULL) ^ getpid();
    return session_key;
}
