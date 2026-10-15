#include <unistd.h>
#include <stdio.h>

int scan_dirs(const char **dirs, int n)
{
	uid_t me = getuid();
~>	seteuid(0);
	for (int i = 0; i < n; i++) {
		if (dirs[i] == NULL)
			return -1;
		puts(dirs[i]);
	}
	seteuid(me);
	return 0;
}
