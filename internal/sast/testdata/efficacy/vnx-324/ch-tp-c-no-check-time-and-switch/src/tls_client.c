#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err = @@sample:X[5]09[_]ST[O]RE[_]CT[X][_]g[e]t[_][e]rr[o]r@@(ctx);

    switch (err) {
~>    case @@sample:X[5]09[_]V[_][E]RR[_]CE[R]T[_][H]AS[_]EX[P]IR[E]D@@:
        return 1;
    default:
        return preverify_ok;
    }
}

int configure(SSL_CTX *ctx)
{
    X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
~>    @@sample:X[5]09[_]VE[R]IF[Y][_]P[A]RA[M][_]s[e]t[_][f]la[g]s@@(param, @@sample:X[5]09[_]V[_][F]LA[G][_]N[O][_]C[H]EC[K][_]T[I]ME@@);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
    return 0;
}
