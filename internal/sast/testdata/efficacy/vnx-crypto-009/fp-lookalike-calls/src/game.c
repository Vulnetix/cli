#include <stdlib.h>

int my_rand(void);
static int xrand(struct rng *r);

void roll(struct game *g, struct rng *rng)
{
    g->token = my_rand();
    g->nonce = rng->random();
    g->secret = xrand(rng);
    g->password_hint = brand(g);
    g->session_operand = operand(3);
    int csrf_len = 32;
    unsigned int token = arc4random();
}
