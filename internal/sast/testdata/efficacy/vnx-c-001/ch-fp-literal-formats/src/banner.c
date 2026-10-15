#include <stdio.h>
#include <string.h>

#define VERSION "1.2.3"

void banner(char *buf, int major, int minor)
{
	sprintf(buf, "v%d.%d", major, minor);
	strcpy(buf, "ready");
	strcat(buf, " " VERSION);
	sprintf(buf, "100%% done %d", major);
	strcpy(buf, major ? "on" : "off");
}
