/* free(password) must be preceded by explicit_bzero */
// realloc(secret, n) leaves a copy behind
static const char *msg = "free(password) leaks";
