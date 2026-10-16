#include <unistd.h>

extern void run_unprivileged(void);

void maybe_run(uid_t uid)
{
	if (setuid(uid) == 0) {
		run_unprivileged();
	}
}
