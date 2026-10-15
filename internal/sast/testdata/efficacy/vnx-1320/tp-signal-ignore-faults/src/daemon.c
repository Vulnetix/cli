#include <signal.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
~>	signal(SIGSEGV, SIG_IGN);
~>	signal( SIGBUS , SIG_IGN );
~>	(void)signal(SIGFPE, SIG_IGN);
	return run(argc, argv);
}
