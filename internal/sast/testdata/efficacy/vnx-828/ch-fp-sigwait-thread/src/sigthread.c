#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void *signal_thread(void *arg)
{
	sigset_t *set = arg;
	int sig;
	for (;;) {
		sigwait(set, &sig);
		printf("got signal %d\n", sig);
		if (sig == SIGTERM)
			exit(0);
	}
	return NULL;
}

int start(pthread_t *t, sigset_t *set)
{
	pthread_sigmask(SIG_BLOCK, set, NULL);
	return pthread_create(t, NULL, signal_thread, set);
}
