#include <signal.h>
#include <stdlib.h>

static void daemon_init(void)
{
~>	(void)signal(SIGFPE, SIG_IGN);
~>	signal ( SIGBUS , SIG_IGN );
	signal(SIGPIPE, SIG_IGN);
}
