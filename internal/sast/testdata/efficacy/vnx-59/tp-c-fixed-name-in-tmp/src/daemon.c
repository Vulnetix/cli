#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_pid(void) {
    int fd = open("/tmp/appd.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dprintf(fd, "%d\n", getpid());
    close(fd);
}

static void log_line(const char *msg) {
    FILE *f = fopen("/tmp/appd.log", "a");
    fputs(msg, f);
    fclose(f);
}

static void dump_state(int id) {
    char path[256];
    snprintf(path, sizeof(path), "/var/tmp/appd-%d.state", id);
    FILE *out = fopen(path, "w");
    fclose(out);
~>    chmod("/tmp/appd.sock", 0777);
}

static int take_lock(void) {
    char *lock = "/tmp/appd.lock";
    int fd = open(lock, O_RDWR | O_CREAT, 0644);
    return fd;
}
