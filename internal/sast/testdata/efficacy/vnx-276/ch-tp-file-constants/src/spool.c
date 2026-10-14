#include <sys/stat.h>
#include <unistd.h>

#define LOG_MODE 0666
static const mode_t kSockMode = 0777;
#define PID_MODE 0644

struct spool {
	const char *log_path;
	const char *sock_path;
	const char *pid_path;
};

/* Opens the spool's files and publishes them to the printer daemon,
 * which runs as a different user. */
int spool_publish(const struct spool *s)
{
	if (access(s->log_path, F_OK) != 0)
		return -1;
~>	if (chmod(s->log_path, LOG_MODE) != 0)
		return -1;
~>	if (chmod(s->sock_path, kSockMode) != 0)
		return -1;
	return chmod(s->pid_path, PID_MODE);
}
