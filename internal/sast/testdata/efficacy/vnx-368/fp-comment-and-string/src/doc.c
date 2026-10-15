#include <stdio.h>
#include <pthread.h>

/* seteuid(0) here would make every thread root */
// seteuid(0);
static const char *hint = "seteuid(0) then seteuid(user)";

int show(void)
{
	puts(hint);
	return 0;
}
