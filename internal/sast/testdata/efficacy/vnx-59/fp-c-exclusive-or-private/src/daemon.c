#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

static int safe_files(void) {
    int fd = open("/tmp/appd.pid", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int fd2 = open("/tmp/appd.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    char tmpl[] = "/tmp/appd-XXXXXX";
    int fd3 = mkstemp(tmpl);
    FILE *in = fopen("/tmp/appd.conf", "r");
    FILE *state = fopen("/var/lib/appd/state", "w");
    /* never: fopen("/tmp/appd.log", "w") */
    printf("writing to /tmp/appd.log with fopen(\"/tmp/x\", \"w\")\n");
    return fd + fd2 + fd3 + (in != NULL) + (state != NULL);
}
