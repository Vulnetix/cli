#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void log_event(const char *user, int code)
{
    const char *log_format = getenv("APP_LOG_FORMAT");
    if (log_format == NULL)
        return;
~>    fprintf(stderr, log_format, user, code);
}

int main(int argc, char **argv)
{
    if (argc > 2)
~>        printf(argv[1], argv[2]);
    log_event("root", 0);
    return 0;
}
