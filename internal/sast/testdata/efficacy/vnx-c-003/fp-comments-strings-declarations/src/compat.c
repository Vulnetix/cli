#include <stdio.h>

int system(const char *command);
FILE *popen(const char *command, const char *type);

struct runner {
    int (*system)(const char *);
};

/*
   Previously: system(cmd) after building cmd from the request.
*/

void notes(struct runner *r, struct runner local, const char *cmd)
{
    // system(cmd);
    log_info("system(cmd) failed for %s", cmd);
    r->system(cmd);
    local.system(cmd);
    run_system(cmd);
    my_popen(cmd, "r");
}
