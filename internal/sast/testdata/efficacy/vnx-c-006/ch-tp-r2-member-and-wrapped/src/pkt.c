#include <alloca.h>
#include <string.h>
#include <stdlib.h>

struct pkt { size_t len; const char *name; };

void pkt_copy(const struct pkt *p)
{
~>	char *scratch = alloca(p->len);
	memcpy(scratch, p->name, p->len);
~>	char *joined = __builtin_alloca(
		strlen(p->name) + 16);
	strcpy(joined, p->name);
~>	char *dup = strdupa(p->name);
	(void)dup;
}

void parse_opts(char **argv)
{
	long width = strtol(argv[1], NULL, 0);
~>	double row[width];
	row[0] = 0;
}
