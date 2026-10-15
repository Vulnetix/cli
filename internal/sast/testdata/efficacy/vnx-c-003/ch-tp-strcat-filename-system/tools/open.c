#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void open_file(void)
{
	char line[200];
	char cmd[300] = "xdg-open ";
	if (!fgets(line, sizeof line, stdin))
		return;
	strcat(cmd, line);
~>	system(cmd);
}
