#include <stdio.h>
#include <unistd.h>

int run_hook(const char *hook, char *const argv[])
{
	if (euidaccess(hook, X_OK) == -1) {
		fprintf(stderr, "hook %s not executable\n", hook);
		return -1;
	}
~>	execv(hook, argv);
	return -1;
}
