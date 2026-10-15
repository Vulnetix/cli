#include <stdio.h>

const char *reason(int code)
{
    const char *text;
    int retry;

~>    switch (code) {
    case 200:
        text = "OK";
        retry = 0;
        break;
    case 503:
        text = "Service Unavailable";
        retry = 1;
        break;
    }

    if (retry)
        fprintf(stderr, "retrying\n");
    return text;
}
