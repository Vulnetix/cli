#include <unistd.h>

/* fd = open(path, O_RDWR) without O_CLOEXEC leaks into execvp() children. */
// sock = socket(AF_INET, SOCK_STREAM, 0); system("x");
void noop(void) { puts("fd = open(path, O_RDWR); execvp(cmd)"); }
