#include <stdio.h>
/* never do signal(SIGSEGV, SIG_IGN); */
// signal(SIGBUS, SIG_IGN);
const char *warn = "signal(SIGFPE, SIG_IGN) hides faults";
int main(void) { puts(warn); return 0; }
