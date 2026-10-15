#include <signal.h>

void plugin_load(void)
{
~>	signal(SIGILL,
	       SIG_IGN);
}
