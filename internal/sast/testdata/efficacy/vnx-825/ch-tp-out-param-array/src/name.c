#include <stdio.h>

int get_name(int id, char **out)
{
	char name[32];
	snprintf(name, sizeof(name), "user-%d", id);
~>	*out = name;
	return 0;
}
