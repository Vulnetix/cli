#include <stdio.h>
#include <unistd.h>

FILE *open_report(const char *name)
{
	FILE *fp = NULL;
~>	if (access(name, F_OK) == 0 && (fp = fopen(name, "a")) != NULL) {
		return fp;
	}
	return NULL;
}
