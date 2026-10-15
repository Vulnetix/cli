#include <signal.h>
#include <stdlib.h>

static char *cache;
int counter;

static void cleanup(void)
{
	free(cache);
	cache = NULL;
	counter++;
}

static void on_int(int sig)
{
	_exit(1);
}

int main(void)
{
	signal(SIGINT, on_int);
	atexit(cleanup);
	return 0;
}
