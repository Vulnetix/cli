#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const char *names[8];
static int slots[32];

void terminate_names(void)
{
~>	names[ARRAY_SIZE(names)] = NULL;
}

void reset_last(void)
{
~>	slots[sizeof(slots) / sizeof(slots[0])] = 0;
}

void clear_tail(char *label)
{
	char tmp[64];
	strncpy(tmp, label, sizeof tmp);
~>	tmp[sizeof tmp] = '\0';
}
