#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int install_files(const char *conf, const char *sock, int logfd)
{
	mode_t shared = 0777;

~>	chmod(conf, 0777);
~>	fchmod(logfd, 0666);
~>	chmod(sock, S_IRWXU | S_IRWXG | S_IRWXO);
~>	fchmodat(AT_FDCWD, "/var/lib/app/state", 0646, 0);
~>	chmod("/var/lib/app/cache", shared);
~>	system("chmod -R 777 /var/lib/app/plugins");
	return 0;
}
