#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int slots[32];

void terminate(char *src)
{
	char buf[128];
	strncpy(buf, src, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
	slots[ARRAY_SIZE(slots) - 1] = 0;
	char *end = &buf[sizeof(buf)];
	int *stop = &slots[ARRAY_SIZE(slots)];
	(void)end;
	(void)stop;
}
