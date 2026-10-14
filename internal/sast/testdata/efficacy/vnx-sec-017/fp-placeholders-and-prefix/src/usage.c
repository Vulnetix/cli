#include <string.h>

static const char *usage =
    " -u <uri>   Server URI on format redis://user:password@host:port/dbnum\n";

int is_ldap(const char *url) {
    return strncmp(url, "ldap://", 7) == 0 || strncmp(url, "ftp://", 6) == 0;
}

const char *example = "amqp://user:pass@broker.example.com:5672/";
const char *templ = "ldap://${LDAP_HOST}:389";
