#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <stdexcept>

namespace net {

SSL_CTX* createContext(const char* caFile) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        throw std::runtime_error("SSL_CTX_new failed");
    }
    SSL_CTX_load_verify_locations(ctx, caFile, nullptr);
    X509_VERIFY_PARAM* param = SSL_CTX_get0_param(ctx);
~>    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    return ctx;
}

}  // namespace net
