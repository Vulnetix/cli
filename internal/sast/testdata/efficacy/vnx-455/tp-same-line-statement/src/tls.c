#include <openssl/ssl.h>
#include <syslog.h>

void tls_boot(void)
{
~>    if (!OPENSSL_init_ssl(0, NULL)) syslog(LOG_ERR, "openssl init failed");
~>    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) puts("curl init failed");
    serve_forever();
}
