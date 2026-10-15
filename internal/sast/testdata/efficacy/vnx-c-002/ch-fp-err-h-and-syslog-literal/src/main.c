#include <err.h>
#include <stdlib.h>
#include <syslog.h>

#define MSG_USAGE "usage: tool FILE\n"

int main(int argc, char **argv)
{
	if (argc < 2)
		errx(EXIT_FAILURE, MSG_USAGE);
	if (!open_file(argv[1]))
		err(1, "%s", argv[1]);
	err(1, NULL);
	syslog(LOG_ERR, "%m");
	syslog(LOG_INFO, "started %s", argv[0]);
	printf(MSG_USAGE);
	return 0;
}
