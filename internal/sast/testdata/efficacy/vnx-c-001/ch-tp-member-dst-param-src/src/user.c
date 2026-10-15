#include <string.h>
#include "user.h"

void user_set_name(struct user *u, const char *name)
{
~>	strcpy(u->name, name);
	u->dirty = 1;
}

void user_append_tag(struct user *u, const char *tag)
{
	strcat(u->tags, ",");
~>	strcat(u->tags, tag);
}
