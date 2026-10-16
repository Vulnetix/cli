#include <netdb.h>
#include <stdio.h>
#include <string.h>

int resolve_tenant(const char *tenant, struct addrinfo **res)
{
	struct addrinfo hints;
	char host[64];

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
~>	snprintf(host, sizeof(host), "%s.internal.example.com", tenant);
	return getaddrinfo(host, "443", &hints, res);
}
