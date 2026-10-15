#include <string.h>

int split_header(char *hdr);

int handle_request(char *headers)
{
    char *h = strtok(headers, "\r\n");
    int n = 0;
    while (h) {
~>        n += split_header(h);
        h = strtok(NULL, "\r\n");
    }
    return n;
}

int split_header(char *hdr)
{
    char *name = strtok(hdr, ":");
    return name ? 1 : 0;
}
