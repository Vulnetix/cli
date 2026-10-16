#include <pwd.h>
#include <stdio.h>
#include <unistd.h>

extern void serve_clients(void);

int main(void)
{
	struct passwd *pw = getpwnam("www");
	if (pw == NULL)
		return 1;
~>	if (setgid(pw->pw_gid) != 0) {
		perror("setgid");
	}
~>	if (setuid(pw->pw_uid) == -1) {
		fprintf(stderr, "warning: still running as root, return code ignored\n");
	}
	serve_clients();
	return 0;
}
