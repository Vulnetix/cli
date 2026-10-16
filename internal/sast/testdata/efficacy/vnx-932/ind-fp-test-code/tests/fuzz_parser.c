#pragma GCC optimize("no-stack-protector")
#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 0
int fuzz(void) { return 0; }
