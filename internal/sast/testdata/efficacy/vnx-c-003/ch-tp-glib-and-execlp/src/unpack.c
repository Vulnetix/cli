#include <glib.h>
#include <stdlib.h>
#include <unistd.h>

void unpack(int argc, char **argv)
{
	char *file = argv[1];
	char *cmd = g_strdup_printf("unzip -o %s", file);
~>	FILE *p = popen(cmd, "r");
	pclose(p);
}

void hook(void)
{
	const char *cmd = getenv("POST_HOOK");
~>	execlp("sh", "sh", "-c", cmd, (char *)NULL);
}
