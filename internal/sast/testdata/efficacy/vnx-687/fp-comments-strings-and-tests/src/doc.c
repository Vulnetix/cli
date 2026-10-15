#include <stdio.h>
/* mkdir(dir, 755) is decimal: write 0755 */
// strncat(buf, s, sizeof(buf));
static const char *tip = "fopen(path, \"rw\") is not a mode";
static const char *cmd = "chmod 755 /tmp/x";
int main(void) {
    char buf[64];
    printf("%s %s\n", tip, cmd);
    snprintf(buf, sizeof(buf), "%d", 755);
    return 0;
}
