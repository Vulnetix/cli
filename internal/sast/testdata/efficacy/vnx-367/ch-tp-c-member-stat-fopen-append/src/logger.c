#include <stdio.h>
#include <sys/stat.h>

struct cfg { const char *logfile; };

FILE *open_log(struct cfg *cfg)
{
	struct stat st;
	if (stat(cfg->logfile, &st) == 0 && S_ISREG(st.st_mode)) {
~>		return fopen(cfg->logfile, "a");
	}
	return NULL;
}
