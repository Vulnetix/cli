#include "status.h"

const char *status_text(int code)
{
    const char *text;

    switch (code) {
    case 200:
        text = "OK";
        break;
    case 404:
        text = "Not Found";
        break;
    default:
        text = "Unknown";
        break;
    }
    return text;
}
