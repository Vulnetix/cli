#include <unistd.h>
#include "net.h"

#define MAX_RETRIES 5

int connect_with_retry(const char *host)
{
    int attempts;

~>    while (attempts < MAX_RETRIES) {
        if (net_connect(host) == 0)
            return 0;
        attempts = attempts + 1;
        sleep(1);
    }
    return -1;
}
