#include <openssl/crypto.h>

int sign_blob(const unsigned char *in, size_t len)
{
	unsigned char *der = NULL;
	int rc = -1;

	der = OPENSSL_malloc(len);
	if (encode(in, len, der) < 0) {
~>		OPENSSL_free(der); goto done;
	}
	rc = 0;
done:
	OPENSSL_free(der);
	return rc;
}
