#include <openssl/x509_vfy.h>
#include <syslog.h>

int strict_verify_cb(int ok, X509_STORE_CTX *store)
{
    int err = X509_STORE_CTX_get_error(store);

    if (!ok && err == X509_V_ERR_CERT_HAS_EXPIRED) {
        syslog(LOG_WARNING, "rejecting expired peer certificate");
        return 0;
    }
    return ok;
}
