#include <stdio.h>
#include <string.h>

static const char kDefaultLabel[] = "untitled";

void label_reset(char label[32], int id, const char *name, size_t len)
{
	strcpy(label, kDefaultLabel);
	sprintf(label, "%.*s", (int)len, name);
	sprintf(label, "item-%d-%u", id, (unsigned)len);
	sprintf(label, "%.20s#%d", name, id);
	snprintf(label, 32, "%s", name);
	strlcpy(label, name, 32);
}

int read_code(char code[16])
{
	return scanf("%15s", code);
}
