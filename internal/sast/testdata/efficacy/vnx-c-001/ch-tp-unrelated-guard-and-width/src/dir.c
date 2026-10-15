#include <dirent.h>
#include <string.h>
#include <stdio.h>

void list_dir(DIR *d, const char *prefix)
{
	char out[1024] = "";
	char row[80];
	struct dirent *e;
	if (strlen(prefix) > 64)
		return;
	strcpy(out, prefix);
	while ((e = readdir(d)) != NULL) {
~>		strcat(out, e->d_name);
~>		sprintf (row, "%-20s|", e->d_name);
	}
}
