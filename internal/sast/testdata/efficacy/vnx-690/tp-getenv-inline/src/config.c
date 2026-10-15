#include <stdlib.h>
#include <string.h>

static char home[256];

void load_home(void) {
~>    strcpy(home, getenv("HOME"));
}

size_t shell_len(void) {
~>    return strlen(getenv( "SHELL" ));
}

int debug_level(void) {
~>    return atoi(getenv("APP_DEBUG"));
}

char first_lang(void) {
~>    return getenv("LANG")[0];
}
