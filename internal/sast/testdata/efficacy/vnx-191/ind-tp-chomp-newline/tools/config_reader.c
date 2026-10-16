#include <stdio.h>
#include <string.h>

static void trim_newline(char *line)
{
~>	if (line[strlen(line) - 1] == '\n')
~>		line[strlen(line) - 1] = '\0';
}

int load_config(const char *path)
{
	char buf[256];
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(buf, sizeof(buf), f)) {
		trim_newline(buf);
		puts(buf);
	}
	fclose(f);
	return 0;
}
