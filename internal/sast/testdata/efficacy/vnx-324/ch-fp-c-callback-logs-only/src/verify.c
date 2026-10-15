#include <stdio.h>
#include <openssl/ssl.h>

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err = @@sample:X[5]09[_]ST[O]RE[_]CT[X][_]g[e]t[_][e]rr[o]r@@(ctx);
    if (err == @@sample:X[5]09[_]V[_][E]RR[_]CE[R]T[_][H]AS[_]EX[P]IR[E]D@@) {
        fprintf(stderr, "peer certificate has expired\n");
    }
    return preverify_ok;
}

void install(SSL_CTX *ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
}
