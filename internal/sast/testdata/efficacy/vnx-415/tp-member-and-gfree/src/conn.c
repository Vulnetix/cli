#include <openssl/crypto.h>
#include <stdlib.h>

void conn_close(struct conn *conn)
{
    OPENSSL_free(conn->secret);
    shutdown_socket(conn->fd);
    std_close(conn);
~>  OPENSSL_free( conn->secret );
}

void release_names(char **names)
{
    kfree(names[0]);
    free((void *) names);
~>  free( (void *)names );
}
