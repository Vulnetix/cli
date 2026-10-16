#include <signal.h>
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void flush_and_quit(int sig)
{
    pthread_mutex_lock(&log_lock);
    flush_log_buffers();
    pthread_mutex_unlock(&log_lock);
    _exit(0);
}

int main(void)
{
~>    signal(SIGINT, flush_and_quit);
~>    signal(SIGUSR1, flush_and_quit);
    for (;;)
        pause();
}
