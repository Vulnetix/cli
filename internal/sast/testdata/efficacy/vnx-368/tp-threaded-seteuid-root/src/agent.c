#include <pthread.h>
#include <unistd.h>

static void *worker(void *arg)
{
	return arg;
}

int rotate_logs(uid_t user)
{
	pthread_t t;
	pthread_create(&t, NULL, worker, NULL);
~>	if (seteuid(0) != 0)
		return -1;
	unlink("/var/log/agent.log.1");
	seteuid(user);
	return 0;
}
