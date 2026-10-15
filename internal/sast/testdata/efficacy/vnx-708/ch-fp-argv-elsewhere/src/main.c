#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

static void reset_owner(const char *path) {
    struct stat st;
    if (stat("/etc/app/template", &st) == 0) {
        chown(path, st.st_uid, st.st_gid);
    }
}

int main(int argc, char **argv) {
    const char *name = "/var/lib/app/state";
    if (argc > 1) {
        fprintf(stderr, "ignoring %s\n", argv[1]);
    }
    reset_owner(name);
    return 0;
}
