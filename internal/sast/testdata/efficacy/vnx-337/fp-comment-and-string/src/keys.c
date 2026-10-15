#include <stdio.h>
#include <sys/random.h>

/* srand(time(NULL)) would make every token guessable */
static const char *HINT = "do not call srand(time(NULL)) before making a token";

void make_token(unsigned char *token, size_t n) {
    getrandom(token, n, 0);
}
