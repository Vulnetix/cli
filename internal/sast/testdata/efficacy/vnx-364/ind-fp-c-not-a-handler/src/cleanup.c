#include <stdlib.h>
#include <signal.h>

static char *scratch;
static int exiting;

static void release_scratch(void)
{
	free(scratch);
	scratch = NULL;
	exiting = 1;
}

static void reset_state(int code)
{
	exiting = code;
}

static void on_int(int sig)
{
	int exiting = sig;  /* shadows the global */
	exiting++;
	(void)exiting;
}

int cleanup_init(void)
{
	scratch = malloc(4096);
	atexit(release_scratch);
	reset_state(0);
	signal(SIGINT, on_int);
	return 0;
}
