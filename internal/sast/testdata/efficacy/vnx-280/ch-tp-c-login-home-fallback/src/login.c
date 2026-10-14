#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void enter_home(const struct passwd *pw)
{
~>	if (chdir(pw->pw_dir) == -1) {
		fprintf(stderr, "no home directory %s, logging in with home = /\n", pw->pw_dir);
		if (chdir("/") == -1)
			exit(1);
	}
}
