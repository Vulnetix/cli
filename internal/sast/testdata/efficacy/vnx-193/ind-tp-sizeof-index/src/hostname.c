#include <string.h>
#include <unistd.h>

int read_hostname(char *out, size_t out_len)
{
	char host[256];

	if (gethostname(host, sizeof(host)) != 0)
		return -1;
~>	host[sizeof(host)] = '\0';
	strncpy(out, host, out_len - 1);
	out[out_len - 1] = '\0';
	return 0;
}
