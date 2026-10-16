#include <signal.h>
#include <stdlib.h>
#include <string.h>

static char *config_text;

static void reload_handler(int signo)
{
    (void)signo;
    free(config_text);
    config_text = malloc(8192);
    load_config_into(config_text, 8192);
}

int setup_reload(void)
{
    struct sigaction act = {
        .sa_handler = reload_handler,
~>        .sa_flags = SA_NODEFER,
    };
    sigemptyset(&act.sa_mask);
    return sigaction(SIGHUP, &act, NULL);
}
