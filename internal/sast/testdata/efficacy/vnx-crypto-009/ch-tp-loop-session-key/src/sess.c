#include <stdlib.h>
#include <stdio.h>
struct conn { char session_key[33]; unsigned nonce; };
void issue(struct conn *c) {
    for (int i = 0; i < 32; i++)
~>        c->session_key[i] = "0123456789abcdef"[rand() % 16];
~>    c->nonce = (unsigned)random();
}
