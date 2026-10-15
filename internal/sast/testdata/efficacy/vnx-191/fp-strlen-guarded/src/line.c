#include <string.h>

void chomp(char *line)
{
	size_t n = strlen(line);
	if (n > 0 && line[n - 1] == '\n')
		line[n - 1] = '\0';
	if (*line && line[strlen(line) - 1] == '\r')
		line[strlen(line) - 1] = '\0';
}
