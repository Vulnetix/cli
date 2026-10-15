#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

static int verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err = @@sample:X[5]09[_]ST[O]RE[_]CT[X][_]g[e]t[_][e]rr[o]r@@(ctx);
~>    if (err == @@sample:X[5]09[_]V[_][E]RR[_]CE[R]T[_][H]AS[_]EX[P]IR[E]D@@) {
        return 1;
    }
    return preverify_ok;
}

static int verify_cb2(int ok, X509_STORE_CTX *ctx)
{
    switch (@@sample:X[5]09[_]ST[O]RE[_]CT[X][_]g[e]t[_][e]rr[o]r@@(ctx)) {
~>    case @@sample:X[5]09[_]V[_][E]RR[_]CE[R]T[_][H]AS[_]EX[P]IR[E]D@@:
~>    case @@sample:X[5]09[_]V[_][E]RR[_]CE[R]T[_][N]OT[_]YE[T][_]V[A]LI[D]@@:
        @@sample:X[5]09[_]ST[O]RE[_]CT[X][_]s[e]t[_][e]rr[o]r@@(ctx, X509_V_OK);
        return 1;
    default:
        return ok;
    }
}

void setup(SSL_CTX *c)
{
    SSL_CTX_set_verify(c, SSL_VERIFY_PEER, verify_cb);
}
