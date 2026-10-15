#include <stdio.h>
#include <limits.h>

static char cache_path[PATH_MAX];

const char *cache_file(const char *dir, const char *file)
{
~>	sprintf(cache_path,
	        "%s/%s.cache",
	        dir, file);
	return cache_path;
}

void log_user(char *out, const char *who, int id)
{
~>	sprintf(out, "user=%s id=%d", who, id);
}
