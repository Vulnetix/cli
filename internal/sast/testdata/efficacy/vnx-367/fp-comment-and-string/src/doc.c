#include <stdio.h>

/* Never do: if (access(path, W_OK) == 0) fd = open(path, O_WRONLY); */
// access(path, W_OK) followed by open(path, ...) is a race
static const char *msg = "access(path) then open(path, O_WRONLY)";

int show(void)
{
	puts(msg);
	return 0;
}
