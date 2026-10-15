#include <stdio.h>
#include <syslog.h>

#define LOG_FMT "%s: %d\n"

static const char *const level_names[] = { "debug", "info", "warn" };

void log_line(int level, const char *msg, int code)
{
	printf(LOG_FMT, msg, code);
	printf("%s", msg);
	fprintf(stderr, "[%s] %s\n", level_names[level], msg);
	syslog(LOG_ERR, "%s", msg);
	fputs(msg, stderr);
	printf("done\n");
	printf(level ? "warn\n" : "ok\n");
}
