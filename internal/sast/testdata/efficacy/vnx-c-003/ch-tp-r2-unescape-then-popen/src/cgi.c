#include <stdio.h>
#include <stdlib.h>

extern void url_unescape(char *s);
extern void invalidate_cache(void);

int lookup_host(void)
{
	char cmd[512];
	char *q = getenv("QUERY_STRING");
	if (q == NULL)
		return 1;
	url_unescape(q);
	invalidate_cache();
	snprintf(cmd, sizeof cmd, "nslookup %s", q);
~>	FILE *p = popen(cmd, "r");
	if (p)
		pclose(p);
	return 0;
}
