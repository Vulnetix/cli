#include <stdio.h>
#include <syslog.h>
#include <libintl.h>

#define _(s) gettext(s)
#define COLOR_RED "\x1b[31m"
#define COLOR_RESET "\x1b[0m"
#define LOG_COLOR_BOLD "\x1b[1m"

void output(const char *user_msg, const char *prog, int n, int verbose)
{
    char buf[64];

    printf("%s", user_msg);
    fprintf(stderr, "error: %s\n", user_msg);
    syslog(LOG_INFO, "%s", user_msg);
    printf(
        "%d items for %s\n", n, user_msg);
    fprintf(stderr,
            "usage: %s [-v]\n", prog);
    printf(COLOR_RED "failed" COLOR_RESET "\n");
    printf(LOG_COLOR_BOLD);
    printf(_("Usage: %s FILE\n"), prog);
    printf(verbose ? "verbose\n" : "quiet\n");
    snprintf(buf, sizeof(buf), "%d", n);
    printk(KERN_INFO "loaded %d entries\n", n);
    fputs(user_msg, stdout);
    puts(user_msg);
}
