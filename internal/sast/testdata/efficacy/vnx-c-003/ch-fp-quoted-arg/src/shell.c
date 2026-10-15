#include <glib.h>
#include <stdlib.h>

/* system(cmd) with user data is dangerous */
void open_doc(const char *path)
{
	const char *msg = "system(argv[1]) is forbidden";
	puts(msg);
}

int run_cmd(const char *cmd)
{
	return system(cmd);
}
