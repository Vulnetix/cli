#include <curl/curl.h>
#include <stdio.h>

int app_start(void)
{
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) { fprintf(stderr, "curl init failed\n"); return 1; }
    if (sodium_init() < 0)
    {
        fprintf(stderr, "libsodium unavailable\n");
        goto fail;
    }
    return 0;
fail:
    curl_global_cleanup();
    return 1;
}
