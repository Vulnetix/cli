#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

void ok(const char *dir, const char *path, const char *file, int fd) {
    char full[256];
    char line[128];
    full[0] = '\0';
    strncat(full, file, sizeof(full) - strlen(full) - 1);
    strncpy(full, file, sizeof(full) - 1);
    fgets(line, sizeof(line), stdin);
    read(fd, line, sizeof(line) - 1);
    char *copy = malloc(sizeof(line) + 1);
    mkdir(dir, 0755);
    chmod(path, S_IRUSR | S_IWUSR);
    int f2 = open(path, O_WRONLY | O_CREAT, 0600);
    FILE *a = fopen(path, "r+");
    FILE *b = fopen(path, "rb");
    FILE *c = fopen(path, "wbx");
    FILE *d = fopen(path, "a+e");
    sleep(755);
}
