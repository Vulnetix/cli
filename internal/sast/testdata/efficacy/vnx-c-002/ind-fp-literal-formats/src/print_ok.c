#include <stdio.h>
#include <syslog.h>
#include <libintl.h>

#define _(s) gettext(s)
#define COLOR_GREEN "\033[32m"
#define USAGE_FMT "usage: %s [-v] file\n"

void report(const char *msg, int n, const char *prog, int verbose)
{
    printf("%s\n", msg);
    syslog(LOG_INFO, "%s", msg);
    fprintf(stderr, "processed "
                    "%d files\n", n);
    printf(COLOR_GREEN "done\n");
    printf(_("Saved %d files\n"), n);
    fprintf(stderr, USAGE_FMT, prog);
    printf(verbose ? "%d items\n" : "%d\n", n);
    fputs(msg, stderr);
    /* printf(msg) would be wrong here */
}
