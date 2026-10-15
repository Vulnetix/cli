#include <stdio.h>
/* cap_set_flag(caps, CAP_EFFECTIVE, 1, list, CAP_SET) with CAP_SYS_ADMIN is root */
// prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0);
static const char *warn = "never cap_from_text(\"cap_sys_admin+ep\")";
void f(void) { puts(warn); }
