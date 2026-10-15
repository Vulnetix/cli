#include <string.h>

struct config { int verbose; };

static const char *current_name;
struct config *active;

void apply(void);

void set_default_name(void)
{
    char local[16] = "guest";
~>    current_name = local;
}

void load_config(int verbose)
{
    struct config cfg;
    cfg.verbose = verbose;
~>    active = &cfg;
    apply();
}
