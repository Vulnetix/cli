/* Do not add #pragma GCC optimize("no-stack-protector") here */
// __attribute__((no_stack_protector)) is banned
static const char *hint = "compile with -fno-stack-protector and #define _FORTIFY_SOURCE 0";
int x = 1; // #undef _FORTIFY_SOURCE
