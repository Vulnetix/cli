#include <string.h>

#define NAME_MAX_LEN 32

struct entry {
	char name[NAME_MAX_LEN];
};

void set_name(struct entry *e, const char *src)
{
	char tmp[64];
	strncpy(tmp, src, sizeof(tmp));
~>	tmp[sizeof(tmp)] = '\0';
	strncpy(e->name, tmp, NAME_MAX_LEN);
~>	e->name[NAME_MAX_LEN] = 0;
}
