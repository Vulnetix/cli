#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

static void *poller(void *arg)
{
	(void)arg;
	for (;;)
		sleep(1);
	return NULL;
}

int read_device(const char *dev, uid_t user)
{
	int fd;

~>	seteuid(0);
	fd = open(dev, O_RDONLY);
	seteuid(user);
	return fd;
}

int agent_start(void)
{
	pthread_t tid;
	return pthread_create(&tid, NULL, poller, NULL);
}
