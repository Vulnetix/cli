#include <glib.h>
#include <openssl/crypto.h>

void release_peer(struct peer *p)
{
    g_free(p->name);
    g_debug("peer released");
~>    g_free(p->name);
}

void drop_key(unsigned char *key, size_t len)
{
    OPENSSL_cleanse(key, len);
    OPENSSL_free(key);
    stats.keys_dropped++;
~>    OPENSSL_free(key);
}
